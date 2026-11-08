# Configuration

!!! tip "Build your config interactively"
    The [Config builder](config-builder.md) lists every setting below as a form
    field, with its help and `KRAWL_*` variable, and prints the result as
    `config.yaml`, environment variables or Helm values.

Krawl reads `config.yaml` (or the file named by `CONFIG_LOCATION`) and then
applies environment variables, which win. The annotated
[config.yaml](https://github.com/BlessedRebuS/Krawl/blob/main/config.yaml) is
the full reference for the file; the Helm chart exposes the same keys under
`config:` in [values.yaml](https://github.com/BlessedRebuS/Krawl/blob/main/helm/values.yaml).

The running configuration, with secrets hidden, is shown in the dashboard under
**Settings → Configuration**; see [Dashboard](dashboard.md#settings).

## Environment variables

All settings can be supplied as environment variables, which override `config.yaml`.
The variable name is `KRAWL_` plus the setting path in upper case, so `dashboard.password`
becomes `KRAWL_DASHBOARD_PASSWORD`.

<details>
<summary><b>Server and link generation</b> (17 variables)</summary>

How Krawl presents itself and shapes the maze of generated pages.

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `CONFIG_LOCATION` | Path to yaml config file | `config.yaml` |
| `KRAWL_PORT` | Server listening port | `5000` |
| `KRAWL_DELAY` | Response delay in milliseconds | `100` |
| `KRAWL_SERVER_HEADER` | HTTP Server header for deception; empty picks one of `KRAWL_SERVER_HEADERS` | `""` |
| `KRAWL_SERVER_HEADERS` | Comma-separated Server headers to pick from at random | Apache, nginx, IIS, cloudflare, AmazonS3, gunicorn |
| `KRAWL_PROXY_HEADERS` | Comma-separated headers carrying the real client IP behind a proxy, checked in order | `CF-Connecting-IP,X-Forwarded-For,X-Real-IP` |
| `KRAWL_LINKS_LENGTH_RANGE` | Link length range as `min,max` | `5,15` |
| `KRAWL_LINKS_PER_PAGE_RANGE` | Links per page as `min,max` | `10,15` |
| `KRAWL_CHAR_SPACE` | Characters used for link generation | `abcdefgh...` |
| `KRAWL_MAX_COUNTER` | Initial counter value | `10` |
| `KRAWL_PROBABILITY_ERROR_CODES` | Error response probability (0-100%) | `0` |
| `KRAWL_ERROR_CODES` | Comma-separated status codes a trap page picks from | `400,401,403,404,500,502,503` |
| `KRAWL_CREDENTIAL_USERNAME_FIELDS` | Comma-separated form fields read as a username | `username,user,login,email,log,userid,account` |
| `KRAWL_CREDENTIAL_PASSWORD_FIELDS` | Comma-separated form fields read as a password | `password,pass,passwd,pwd,passphrase` |
| `KRAWL_INFINITE_PAGES_FOR_MALICIOUS` | Serve infinite pages to malicious IPs | `true` |
| `KRAWL_MAX_PAGES_LIMIT` | Maximum page limit for crawlers | `250` |
| `KRAWL_BAN_DURATION_SECONDS` | Ban duration in seconds for rate-limited IPs | `600` |

</details>

<details>
<summary><b>Dashboard, metrics and logging</b> (14 variables)</summary>

Dashboard access, cache warmup, Prometheus and log level.

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `KRAWL_DASHBOARD_SECRET_PATH` | Custom dashboard path | Auto-generated |
| `KRAWL_DASHBOARD_PASSWORD` | Password for protected dashboard panels | Auto-generated |
| `KRAWL_DASHBOARD_CACHE_WARMUP` | Pre-compute dashboard data every 5 minutes for instant page loads | `true` |
| `KRAWL_DASHBOARD_WARMUP_PAGES` | Number of pages to pre-warm per table panel | `10` |
| `KRAWL_DASHBOARD_WARMUP_AGGREGATION` | Pre-compute full top_paths/top_ua aggregations for zero-query serving | `false` |
| `KRAWL_DASHBOARD_TOP_N_MIN_COUNT` | Minimum access count for top paths/user agents panels (set to 1 to disable) | `5` |
| `KRAWL_DASHBOARD_BRAND_NAME` | Name in the dashboard wordmark and heading | `Krawl` |
| `KRAWL_DASHBOARD_BRAND_URL` | Where the wordmark links (empty renders it as plain text) | Krawl's repository |
| `KRAWL_DASHBOARD_BRAND_LOGO` | Image URL shown instead of the Krawl mark | Unset |
| `KRAWL_DASHBOARD_BRAND_SHOW_VERSION` | Show the version next to the name | `true` |
| `KRAWL_DASHBOARD_BRAND_CONTACT` | Contact shown under the wordmark (address, URL, or plain text) | Unset |
| `KRAWL_DASHBOARD_DOMAIN_MAP_HOST_LIMIT` | Hostnames drawn per root in the domain link map (1-2000); the rest are summarised | `200` |
| `KRAWL_METRICS_ENABLED` | Expose Prometheus metrics at `/<dashboard_path>/metrics` | `true` |
| `KRAWL_LOG_LEVEL` | Application log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) | `INFO` |

</details>

<details>
<summary><b>Database, retention, map and backups</b> (18 variables)</summary>

Storage location, how long data is kept, and the dump job.

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `KRAWL_DATABASE_PATH` | Database file location | `data/krawl.db` |
| `KRAWL_DATABASE_PERSIST_SUSPICIOUS_ONLY` | Only persist suspicious requests to the access log | `false` |
| `KRAWL_MAP_TILE_URL` | Tile URL template for the dashboard map (`{z}/{x}/{y}`, optional `{s}`/`{r}`) | Esri dark canvas |
| `KRAWL_MAP_TILE_ATTRIBUTION` | Attribution shown on the map | Esri/OSM |
| `KRAWL_MAP_API_KEY` | Appended to every tile request as a query parameter — required by CARTO | _(empty)_ |
| `KRAWL_MAP_TILE_SUBDOMAINS` | Letters substituted for `{s}` in the tile URL | `abcd` |
| `KRAWL_MAP_API_KEY_PARAM` | Name of that query parameter (`api_key`, `apikey`, `key`) | `api_key` |
| `KRAWL_IPV6_IGNORE` | Drop IPv6 requests entirely: still logged to stdout, never persisted, ban-checked or exported | `false` |
| `KRAWL_IPV6_PURGE_EXISTING` | Also delete existing IPv6 rows at the next nightly cleanup, 03:00 (irreversible; requires `KRAWL_IPV6_IGNORE`) | `false` |
| `KRAWL_RETENTION_NON_SUSPICIOUS` | Keep non-suspicious logs, clean IPs and their history this long (`12h`, `30d`, `2w`, `6m`, `1y`) | `30d` |
| `KRAWL_RETENTION_RECHECK_SUSPICIOUS` | Re-check suspicious logs older than this against current rules | `30d` |
| `KRAWL_RETENTION_REEVALUATE_INTERVAL` | Re-score IPs whose last analysis is older than this | `5d` |
| `KRAWL_RETENTION_UNINTERESTING` | Delete random-path crawler GETs after this long | `7d` |
| `KRAWL_RETENTION_OVERALL` | Hard cap on all data, attack evidence included; empty = keep forever | _(empty)_ |
| `KRAWL_DATABASE_RETENTION_DAYS` | Deprecated: days for the two windows above when their own variable is unset | `30` |
| `KRAWL_BACKUPS_PATH` | Path where database dump are saved | `backups` |
| `KRAWL_BACKUPS_CRON` | cron expression to control backup job schedule | `*/30 * * * *` |
| `KRAWL_BACKUPS_ENABLED` | Boolean to enable db dump job | `true` |

</details>

<details>
<summary><b>Traps: tarpit, deception pages and canary</b> (6 variables)</summary>

Opt-in traps and the pages served to attackers.

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `KRAWL_TARPIT_ENABLED` | Trap AI agents with slow responses and random text | `false` |
| `KRAWL_TARPIT_DELAY_SECONDS` | Extra delay in seconds added per response when tarpit is active | `5` |
| `KRAWL_DECEPTION_IMPORT_PAGES` | Auto-import deception pages from `src/templates/deception/` at startup | `true` |
| `KRAWL_CUSTOM_TEMPLATE_PATH` | Path inside the container to a custom HTML template. Template must include `{counter}` and `{content}` placeholders. | `/templates/custom_page.html` |
| `KRAWL_CANARY_TOKEN_URL` | External canary token URL | None |
| `KRAWL_CANARY_TOKEN_TRIES` | Requests before showing canary token | `10` |

</details>

<details>
<summary><b>Detection and background tasks</b> (10 variables)</summary>

Where the YARA rules and fake replies live, and how many rows each scheduled
task handles per run. Raise a batch when its backlog never drains; the defaults
suit a 256Mi pod.

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `KRAWL_YARA_RULES_PATH` | Directory of bundled YARA rules (see [Attack detection](detection.md)) | `rules` |
| `KRAWL_RESPONSES_PATH` | Directory of fake replies: `manifest.yaml` plus files (see [Honeypot](honeypot.md)) | `responses` |
| `KRAWL_TASKS_ANALYZE_IPS_BATCH` | IPs scored per `analyze-ips` run | `2000` |
| `KRAWL_TASKS_EXTRACT_METADATA_BATCH` | Logs parsed per `extract-request-metadata` run | `500` |
| `KRAWL_TASKS_EXTRACT_FILES_BATCH` | Logs scanned per `extract-captured-files` run | `500` |
| `KRAWL_TASKS_HASH_PAYLOADS_BATCH` | Logs hashed per `hash-payloads` run | `500` |
| `KRAWL_TASKS_HASH_PAYLOADS_CHUNK` | Raw requests held in memory at once while hashing | `50` |
| `KRAWL_TASKS_HASH_FILES_BATCH` | Captured files back-filled per run | `50` |
| `KRAWL_TASKS_CLEANUP_BATCH` | Rows per `pre-retention-cleanup` pass | `1000` |
| `KRAWL_TASKS_RETENTION_DELETE_BATCH` | Rows per `db-retention` delete transaction | `10000` |

</details>

<details>
<summary><b>IP reputation analyzer</b> (6 variables)</summary>

Thresholds that decide how an IP gets classified.

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `KRAWL_HTTP_RISKY_METHODS_THRESHOLD` | Threshold for risky HTTP methods detection | `0.1` |
| `KRAWL_VIOLATED_ROBOTS_THRESHOLD` | Threshold for robots.txt violations | `0.1` |
| `KRAWL_UNEVEN_REQUEST_TIMING_THRESHOLD` | Coefficient of variation threshold for timing | `0.5` |
| `KRAWL_UNEVEN_REQUEST_TIMING_TIME_WINDOW_SECONDS` | Time window for request timing analysis in seconds | `300` |
| `KRAWL_USER_AGENTS_USED_THRESHOLD` | Threshold for detecting multiple user agents | `2` |
| `KRAWL_ATTACK_URLS_THRESHOLD` | Threshold for attack URL detection | `1` |

`analyzer.scoring_weights` (the points each signal adds per category) is set in
`config.yaml` only; see [How IPs are evaluated](algorithms.md).

</details>

<details>
<summary><b>Threat-intel capture</b> (4 variables)</summary>

Fuzzy-hash captured payloads (files and flagged request bodies) and group
near-duplicate variants into campaign clusters. Requires `py-tlsh`.

Hashing runs as the scheduled `hash-payloads` background task (see
[`src/tasks/hash_payloads.py`](https://github.com/BlessedRebuS/Krawl/blob/main/src/tasks/hash_payloads.py)), which hashes each captured attack once — new
hits at ingest time, and a one-time backward sweep of existing history
tracked by a `payload_hash_watermark` high-water mark — then clusters the
digests into recurring-pattern campaigns.

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `KRAWL_TLSH_ENABLED` | Hash uploaded files and flagged request bodies with TLSH for near-duplicate clustering | `true` |
| `KRAWL_TLSH_CLUSTER_THRESHOLD` | TLSH distance below which a payload joins an existing campaign (0 = identical bytes; variants of a webshell typically diff < 100) | `150` |
| `KRAWL_TLSH_CAMPAIGN_MIN_EVENTS` | Times a payload must be seen before its campaign appears in the Threats tab | `10` |
| `KRAWL_REFERER_ENABLED` | Record the inbound HTTP Referer on access logs, for bait-chain tracking | `true` |

</details>

<details>
<summary><b>Banlist and ignored IPs</b> (4 variables)</summary>

Sharing banlists with other instances, and traffic to never track.

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `KRAWL_IGNORED_IPS` | Comma-separated IPs/CIDRs never tracked, banned or exported | Loopback, RFC1918, link-local, CGNAT |
| `KRAWL_BANLIST_EXPORT_PATH` | Public banlist download path, e.g. `/public_banlist.txt` (empty = disabled) | `""` |
| `KRAWL_BANLIST_SOURCES` | Comma-separated upstream banlist URLs to fetch and merge | Krawl community banlist |
| `KRAWL_BANLIST_REFRESH_INTERVAL` | Seconds between upstream banlist fetches | `3600` |

</details>

<details>
<summary><b>AI-generated deception pages</b> (10 variables)</summary>

See the [AI Generation documentation](ai_generation.md).

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `KRAWL_AI_ENABLED` | Enable AI-generated deception pages | `false` |
| `KRAWL_AI_PROVIDER` | AI provider (`"openrouter"` or `"openai"`) | `"openrouter"` |
| `KRAWL_AI_OPENAI_BASE_URL` | Optional OpenAI Base URL for custom API endpoints | `"https://api.openai.com/v1"` |
| `KRAWL_AI_API_KEY` | API key for AI provider | `None` |
| `KRAWL_AI_MODEL` | AI model to use for page generation | `"nvidia/nemotron-3-super-120b-a12b:free"` |
| `KRAWL_AI_TIMEOUT` | Request timeout in seconds for AI API calls | `60` |
| `KRAWL_AI_MAX_DAILY_REQUESTS` | Max number of AI-generated pages per day (0 = unlimited) | `0` |
| `KRAWL_AI_PROMPT` | Custom prompt template for AI page generation | Default prompt |
| `KRAWL_AI_REASONING_ENABLED` | Enable reasoning tokens (OpenRouter reasoning models only) | `false` |
| `KRAWL_AI_REASONING_EFFORT` | Reasoning effort (`none`, `minimal`, `low`, `medium`, `high`, `xhigh`) | `"medium"` |

</details>

<details>
<summary><b>Scalable mode: PostgreSQL and Redis</b> (13 variables)</summary>

Only used when `KRAWL_MODE=scalable`. See [Deployment Modes](deployment-modes.md).

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `KRAWL_MODE` | Deployment mode (`standalone` or `scalable`) | `standalone` |
| `KRAWL_POSTGRES_HOST` | PostgreSQL hostname | `localhost` |
| `KRAWL_POSTGRES_PORT` | PostgreSQL port | `5432` |
| `KRAWL_POSTGRES_USER` | PostgreSQL username | `krawl` |
| `KRAWL_POSTGRES_PASSWORD` | PostgreSQL password | `krawl` |
| `KRAWL_POSTGRES_DATABASE` | PostgreSQL database name | `krawl` |
| `KRAWL_REDIS_HOST` | Redis hostname | `localhost` |
| `KRAWL_REDIS_PORT` | Redis port | `6379` |
| `KRAWL_REDIS_DB` | Redis database number | `0` |
| `KRAWL_REDIS_PASSWORD` | Redis password | None |
| `KRAWL_REDIS_CACHE_TTL` | TTL in seconds for dashboard warmup data | `600` |
| `KRAWL_REDIS_HOT_TTL` | TTL in seconds for hot-path data (ban info, IP categories) | `30` |
| `KRAWL_REDIS_TABLE_TTL` | TTL in seconds for paginated dashboard tables | `120` |

</details>


For example

```bash
# Set canary token
export CONFIG_LOCATION="config.yaml"
export KRAWL_CANARY_TOKEN_URL="http://your-canary-token-url"

# Set number of pages range (min,max format)
export KRAWL_LINKS_PER_PAGE_RANGE="5,25"

# Set analyzer thresholds
export KRAWL_HTTP_RISKY_METHODS_THRESHOLD="0.2"
export KRAWL_VIOLATED_ROBOTS_THRESHOLD="0.15"

# Set custom dashboard path and password
export KRAWL_DASHBOARD_SECRET_PATH="/my-secret-dashboard"
export KRAWL_DASHBOARD_PASSWORD="my-secret-password"
```

Example of a Docker run with env variables (standalone mode):

```bash
docker run -d \
  -p 5000:5000 \
  -e KRAWL_MODE=standalone \
  -e KRAWL_PORT=5000 \
  -e KRAWL_DELAY=100 \
  -e KRAWL_DASHBOARD_PASSWORD="my-secret-password" \
  -e KRAWL_CUSTOM_TEMPLATE_PATH="/templates/custom_page.html" \
  -e KRAWL_CANARY_TOKEN_URL="http://your-canary-token-url" \
  --name krawl \
  ghcr.io/blessedrebus/krawl:latest
```

## Web server (container image)

The image's entrypoint passes these to uvicorn. They are read only by the
container, not by `config.yaml`. Krawl runs one worker per container; scale with
replicas.

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `KRAWL_UVICORN_HOST` | Listen address | `0.0.0.0` |
| `KRAWL_UVICORN_LIMIT_CONCURRENCY` | Connections served at once before new ones get 503 | `512` |
| `KRAWL_UVICORN_BACKLOG` | Pending connections queued by the socket | `256` |
| `KRAWL_UVICORN_KEEP_ALIVE` | Seconds an idle keep-alive connection stays open | `5` |
| `KRAWL_UVICORN_GRACEFUL_TIMEOUT` | Seconds in-flight requests get to finish on shutdown | `30` |
| `KRAWL_UVICORN_LIMIT_MAX_REQUESTS` | Restart the worker after this many requests (unset = never) | unset |
