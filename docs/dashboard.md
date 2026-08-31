# Dashboard

Access the dashboard at `http://<server-ip>:<port>/<dashboard-path>`

The Krawl dashboard is a single-page application with **5 tabs**: Overview, Attacks, IP Insight, Tracked IPs, and IP Banlist. The last two tabs are only visible after authenticating with the dashboard password.

---

## Overview

The default landing page provides a high-level summary of all traffic and suspicious activity detected by Krawl.

### Stats Cards

Seven metric cards are displayed at the top:

- **Total Accesses** — total number of requests received
- **Unique IPs** — distinct IP addresses observed
- **Unique Paths** — distinct request paths
- **Suspicious Accesses** — requests flagged as suspicious
- **Honeypot Caught** — requests that hit honeypot endpoints
- **Credentials Captured** — login attempts captured by the honeypot
- **Unique Attackers** — distinct IPs classified as attackers

### Search

A real-time search bar lets you search across attacks, IPs, patterns, and locations. Results are loaded dynamically as you type.

### IP Origins Map

An interactive world map (powered by Leaflet) displays the geolocation of top IP addresses. You can filter by category:

- Attackers
- Bad Crawlers
- Good Crawlers
- Regular Users
- Unknown

The number of displayed IPs is configurable (top 10, 100, 1,000, or all).

Markers cluster as you zoom out, and each cluster is ringed in the proportions
of the categories inside it, so a cluster that is mostly attackers reads red
before you click it. The view fits itself to the visible markers rather than
opening at a fixed zoom, which keeps the framing right on any screen width and
re-fits when you toggle a category off. It will not zoom past a global
overview on load — panning in is left to you.

The basemap is deliberately desaturated so that the category colours are the
only saturated thing on the panel. The bundled offline tiles need no network
access or configuration.

![Overview — Stats and Map](../img/geoip_dashboard.png)

### Recent Suspicious Activity

A table showing the last 10 suspicious requests with IP address, path, user-agent, and timestamp. Each entry provides actions to view the raw HTTP request or inspect the IP in detail.

### Top IP Addresses

A paginated, sortable table ranking IPs by access count. Each IP shows its category badge and can be clicked to expand inline details or open the IP Insight tab.

### Top Paths

A paginated table of the most accessed HTTP paths and their request counts.

### Top User-Agents

A paginated table of the most common user-agent strings with their frequency.

![Overview — Tables](../img/overview_tables_dashboard.png)

---

## Attacks

The Attacks tab focuses on detected malicious activity, attack patterns, and captured credentials.

### Attackers by Total Requests

A paginated table listing all detected attackers ranked by total requests. Columns include IP, total requests, first seen, last seen, and location. Sortable by multiple fields.

![Attacks — Attackers and Credentials](../img/top_attackers_dashboard.png)

### Captured Credentials

A table of usernames and passwords captured from honeypot login forms, with timestamps. Useful for analyzing common credential stuffing patterns.

### Honeypot Triggers by IP

Shows which IPs accessed honeypot endpoints and how many times, sorted by trigger count.

### Detected Attack Types

A detailed table of individual attack detections showing IP, path, attack type classifications, user-agent, request method, size, and timestamp. The size column is sortable, so the heaviest payloads surface first. Each entry can be expanded to view the raw HTTP request.

**Attachments.** When the request carried an upload — a webshell, a malware sample, an exfiltration payload — a paperclip button appears in the raw request modal listing the uploaded files, and downloads the one you click. Both `multipart/form-data` parts and raw-body uploads are recognised. Treat every download as hostile and open it in a sandbox. Requests with bodies above 64 KB are not buffered, so they have no retrievable attachment. The same data is available through the [Dashboard API](dashboard-api.md#attachments).

### Most Recurring Attack Types

A Chart.js visualization showing the frequency distribution of detected attack categories (e.g., SQL injection, path traversal, XSS).

### Most Recurring Attack Patterns

A paginated table of specific attack patterns and their occurrence counts across all traffic.

![Attacks — Attack Types and Patterns](../img/attack_types_dashboard.png)

---

## IP Insight

The IP Insight tab provides a deep-dive view for a single IP address. It is activated by clicking "Inspect IP" from any table in the dashboard.

### IP Information Card

Displays comprehensive details about the selected IP:

- **Activity** — total requests, first seen, last seen, last analysis timestamp
- **Geo & Network** — location, region, timezone, ISP, ASN, reverse DNS
- **Category** — classification badge (Attacker, Good Crawler, Bad Crawler, Regular User, Unknown)

### Ban & Track Actions

When authenticated, admin actions are available:

- **Ban/Unban** — immediately add or remove the IP from the banlist
- **Track/Untrack** — add the IP to your watchlist for ongoing monitoring

### Blocklist Memberships

Shows which threat intelligence blocklists the IP appears on, providing external reputation context.

### Access Logs

A filtered view of all requests made by this specific IP, with full request details.

![IP Insight — Detail View](../img/ip_insight_dashboard.png)

---

## Tracked IPs

> Requires authentication with the dashboard password.

The Tracked IPs tab lets you maintain a watchlist of IP addresses you want to monitor over time.

### Track New IP

A form to add any IP address to your tracking list for ongoing observation.

### Currently Tracked IPs

A paginated table of all manually tracked IPs, with the option to untrack each one.

![Tracked IPs](../img/tracked_ips_dashboard.png)

---

## IP Banlist

> Requires authentication with the dashboard password.

The IP Banlist tab provides tools for managing IP bans. Bans are exported every 5 minutes.

### Force Ban IP

A form to immediately ban any IP address by entering it manually.

### Detected Attackers

A paginated list of all IPs detected as attackers, with quick-ban actions for each entry.

![IP Banlist — Detected](../img/banlist_attackers_dashboard.png)

### Active Ban Overrides

A table of currently active manual ban overrides, with options to unban or reset the override status for each IP.

![IP Banlist — Overrides](../img/banlist_overrides_dashboard.png)

### Export Banlist

A dropdown menu to download the current banlist in two formats:

- **Raw IPs List** — plain text, one IP per line
- **IPTables Rules** — ready-to-use firewall rules

---

## Authentication

The dashboard uses session-based authentication with secure HTTP-only cookies. Protected features (Tracked IPs, IP Banlist, ban/track actions) require entering the dashboard password. The login includes brute-force protection with IP-based rate limiting and exponential backoff.

Sessions and the attempt counters live in Redis in scalable mode, so a cookie issued by one replica is accepted by every other one and the lockout applies per attacker rather than per pod. In standalone mode they are held in-process. Sessions expire after 12 hours, attempt counters after 1 hour.

Click the lock icon in the top-right corner of the navigation bar to authenticate or log out.

![Authentication Modal](../img/auth_prompt.png)

---

## Configuration

Dashboard behaviour is controlled under the `dashboard` section of `config.yaml` (or via environment variables).

### Secret path and password

```yaml
dashboard:
  secret_path: null       # auto-generated at startup if null
  password: null          # auto-generated at startup if null
```

| Env var | Description | Default |
|---|---|---|
| `KRAWL_DASHBOARD_SECRET_PATH` | Custom path for the dashboard | Auto-generated |
| `KRAWL_DASHBOARD_PASSWORD` | Password for protected dashboard panels | Auto-generated |

### Cache warmup

The dashboard pre-computes heavy queries in a background task every 5 minutes so that page loads are instant.

```yaml
dashboard:
  cache_warmup: true       # enable background warmup task
  warmup_pages: 10         # pages to pre-warm per table panel
  warmup_aggregation: false  # pre-compute full top_paths/top_ua aggregations
  top_n_min_count: 5       # minimum access count to appear in top paths/user-agents panels
```

| Env var | Description | Default |
|---|---|---|
| `KRAWL_DASHBOARD_CACHE_WARMUP` | Enable background warmup task | `true` |
| `KRAWL_DASHBOARD_WARMUP_PAGES` | Pages to pre-warm per table panel | `10` |
| `KRAWL_DASHBOARD_WARMUP_AGGREGATION` | Pre-compute full top_paths/top_ua aggregations for zero-query serving | `false` |
| `KRAWL_DASHBOARD_TOP_N_MIN_COUNT` | Minimum access count for top paths/user-agents (set to `1` to disable filtering) | `5` |

> **Scalable mode**: `warmup_aggregation` is enabled by default in Helm and Kubernetes deployments. In standalone mode it is disabled because SQLite handles the load without it.

### Map tiles

The IP Origins Map uses a bundled offline basemap (z0–z6 raster tiles). No tile
provider, API key, or outbound network access is required — the entire pyramid
is shipped inside the repo at `src/templates/static/tiles/` and served as a
static asset. There is intentionally no runtime configuration surface for the
tile source and no build step at deploy time; the tiles are committed to the
repository.

#### Adjusting how the basemap looks

The tiles are desaturated and darkened so the category colours stand out. The
treatment is a single custom property, so you can retune it without touching
the rule:

```css
#attacker-map { --map-tile-filter: saturate(0.35) brightness(0.62) contrast(1.05); }
```

## Design system

The dashboard UI is a console for reading attacker traffic, and the styles are
built around that. Everything visual is defined once, as tokens, at the top of
`src/templates/static/css/dashboard.css`.

### Tokens

| Group | Tokens | Notes |
|---|---|---|
| Surfaces | `--bg` `--surface` `--raised` `--sunken` `--line` `--line-soft` `--scrim` | Deep console canvas, cards one step up |
| Text | `--text` `--text-strong` `--text-dim` `--text-faint` | All AA or better on `--bg` and `--surface` |
| Semantics | `--accent` `--danger` `--warn` `--ok` `--violet` `--pink` `--cyan` | Links and primary actions use `--accent` |
| Categories | `--cat-attacker` `--cat-bad-crawler` `--cat-good-crawler` `--cat-regular-user` `--cat-timed-out` | Threat class, aliased onto the semantics |
| Signal | `--honey` | **Reserved for honeypot triggers.** Nothing else is honey |
| Type | `--font-ui` `--font-mono`, `--fs-2xs` … `--fs-2xl` | Seven steps, no ad-hoc sizes |
| Space | `--s1` … `--s10` | 4px base |
| Radius | `--r-sm` `--r-md` `--r-lg` `--r-pill` | Controls / cards / modals / pills |
| Icons | `--icon-sm` `--icon` `--icon-lg` | 12 / 16 / 20 |

### Rules

- **Log data is mono.** IP addresses, request paths, user agents, timestamps and
  credential pairs use `--font-mono` so columns align and `0`/`O` and `1`/`l`
  stay distinguishable. Labels, prose and controls use `--font-ui`.
- **Honey means a trap was sprung.** Attack volume is red because it is a threat;
  a tripped honeypot is the product working, and it owns the only warm color on
  the page (the two trap-count stat cards and the honeypot trigger counts).
- **One icon system.** Inline Octicon SVGs on a 16 viewBox, sized by `.icon`,
  `.icon-sm` or `.icon-lg`, filled with `currentColor`. No icon webfont.
- **Category colors come from the tokens**, including in JavaScript — `map.js`,
  `radar.js` and `charts.js` read them through `krawlCategoryColors()` in
  `tokens.js`, so a category cannot look one way in a table and another on the map.
- **No `style="…"` in templates.** Add a class to `dashboard.css` instead; the
  component layer at the bottom of the file exists for exactly this. The only
  inline styles left are Alpine's initial `display: none` and colors computed
  per-row on the server.
