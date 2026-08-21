# Dashboard API

Krawl exposes a JSON API for everything the dashboard shows: IP statistics, captured
credentials, attack detections, banlist exports and the Cloudflare integration.

All endpoints live under the dashboard secret path, so a call looks like:

```
https://your-krawl-instance/<DASHBOARD-PATH>/api/export-ips
```

Requests to `/api/...` **without** the secret path prefix are indistinguishable from any
other scan and get a honeypot page — that is intentional.

> Looking for the third-party services Krawl calls out to (geolocation, IP reputation)?
> That's [External APIs](api.md).

## Interactive documentation

Krawl serves a live OpenAPI schema and Swagger UI, always in sync with the running
version:

| Path | Content |
|------|---------|
| `/<DASHBOARD-PATH>/docs` | Swagger UI — browse and try every endpoint |
| `/<DASHBOARD-PATH>/openapi.json` | Raw OpenAPI schema |

Only `/api/*` routes are in the schema; the dashboard pages and HTMX fragment endpoints
are excluded.

## Authentication

Read endpoints are reachable with the secret path alone. Write actions (banning,
tracking, deception page management, webhooks) need a session.

```bash
# Obtain a session cookie
curl -c krawl.cookies -X POST \
  "https://your-krawl-instance/<DASHBOARD-PATH>/api/auth" \
  -H "Content-Type: application/json" \
  -d '{"password": "your-dashboard-password"}'

# Use it
curl -b krawl.cookies -X POST \
  "https://your-krawl-instance/<DASHBOARD-PATH>/api/track-ip" \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "203.0.113.5"}'
```

Sessions are HTTP-only cookies valid for 12 hours. Failed logins are rate-limited per IP
with exponential backoff; in scalable mode both sessions and lockout counters are shared
across replicas via Redis. See [Dashboard → Authentication](dashboard.md#authentication).

Endpoints marked 🔒 below require that session and return `401 {"error": "Unauthorized"}`
without one.

## Endpoints

### Session

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth` | Exchange the dashboard password for a session cookie |
| `POST` | `/api/auth/logout` | Invalidate the current session |
| `GET` | `/api/auth/check` | Report whether the current request is authenticated |

### IP data

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/all-ips` | Paginated list of every observed IP |
| `GET` | `/api/all-ip-stats` | Statistics for all IPs |
| `GET` | `/api/ip-stats/{ip}` | Full detail for one IP: category, scores, geolocation, reputation |
| `GET` | `/api/attackers` | IPs classified as attackers |
| `GET` | `/api/top-ips` | Most active IPs by request count |
| `GET` | `/api/top-paths` | Most requested paths |
| `GET` | `/api/top-user-agents` | Most seen user agents |

### Attacks and captures

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/honeypot` | Honeypot trigger events |
| `GET` | `/api/credentials` | Captured login attempts |
| `GET` | `/api/download-credentials` | Captured credentials as a downloadable file |
| `GET` | `/api/attack-types` | Detected attack attempts |
| `GET` | `/api/attack-types-stats` | Attack counts per type |
| `GET` | `/api/attack-types-daily` | Attack counts per type per day |
| `GET` | `/api/raw-request/{log_id}` | Full raw HTTP request for one access log entry |
| `GET` | `/api/attachments/{log_id}` | Files uploaded in that request — see [Attachments](#attachments) |
| `GET` | `/api/attachments/{log_id}/download/{index}` | Download one of those files |

### Banning and export

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/export-ips` | Export the banlist. Supports `?categories=` and `?fwtype=` — see [Firewall Exporters](firewall-exporters.md) |
| `GET` | `/api/banlist-sources` | Upstream banlists currently merged into the local one |
| `POST` | 🔒 `/api/ban-override` | Manually ban or unban an IP |
| `POST` | 🔒 `/api/timeout-exempt` | Exempt an IP from automatic rate-limit time-bans |
| `POST` | 🔒 `/api/track-ip` | Start tracking an IP |

If `banlist.export_path` is configured, the banlist is also published on that
unauthenticated path outside the dashboard prefix, for other Krawl instances to consume.
See [Krawl Banlist](../README.md#krawl-banlist).

### Deception pages

| Method | Path | Description |
|--------|------|-------------|
| `GET` | 🔒 `/api/download-generated-page` | Download one deception page |
| `POST` | 🔒 `/api/download-generated-pages-zip` | Download a selection as a zip |
| `POST` | 🔒 `/api/upload-generated-page` | Upload one deception page |
| `POST` | 🔒 `/api/upload-generated-pages-bulk` | Upload a zip of deception pages |
| `POST` | 🔒 `/api/delete-generated-pages` | Delete deception pages |

See [Deception Pages](deception_pages.md) for the bulk workflows.

### Cloudflare webhook

| Method | Path | Description |
|--------|------|-------------|
| `GET` | 🔒 `/api/webhooks/status` | Current integration state and last sync result |
| `POST` | 🔒 `/api/webhooks/cloudflare/save` | Store account ID and API token |
| `POST` | 🔒 `/api/webhooks/cloudflare/sync` | Trigger a sync immediately instead of waiting for the interval |
| `DELETE` | 🔒 `/api/webhooks/cloudflare/config` | Remove the stored configuration |

See [Cloudflare Banlist Sync](cloudflare_banlist.md).

### Metrics

Prometheus metrics are served at `/<DASHBOARD-PATH>/metrics`, outside the `/api` prefix
and outside the OpenAPI schema. See [Metrics & Monitoring](monitoring.md).

## Attachments

When an attacker uploads a file — a webshell, a malware sample, an exfiltration payload —
Krawl stores the raw request, and the attachment endpoints let you pull the uploaded
bytes back out for analysis.

Two upload shapes are recognised:

- **`multipart/form-data`** — each part is exposed as a separate attachment, keeping its
  form field name, filename and content type.
- **Raw body uploads** (`PUT`/`POST` of a file as the whole body) — the body becomes a
  single attachment, named after the request path.

```bash
# What did they upload?
curl -b krawl.cookies \
  "https://your-krawl-instance/<DASHBOARD-PATH>/api/attachments/12345"
```

```json
{
  "attachments": [
    {
      "index": 0,
      "name": "file",
      "filename": "shell.php",
      "content_type": "application/x-php",
      "size": 4213
    }
  ]
}
```

```bash
# Pull it down for analysis
curl -b krawl.cookies -OJ \
  "https://your-krawl-instance/<DASHBOARD-PATH>/api/attachments/12345/download/0"
```

In the dashboard the same thing is a paperclip button in the raw request modal: it lists
the attachments and downloads the one you click.

> **Handle downloads as hostile.** These are files an attacker chose to send you. Open
> them in a sandbox, not on the machine running your browser.

Attachments are reconstructed from the stored raw request, which means:

- Request bodies larger than **64 KB** are never buffered, so uploads above that size
  leave a logged request with no retrievable attachment.
- They disappear with the access log itself, on the `database.retention_days` schedule.
