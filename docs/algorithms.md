# Algorithms

How Krawl decides things. Each section: purpose, inputs, steps, a worked example,
config knobs, and known limits.

- [IP evaluation](#ip-evaluation)
- [Request crunching](#request-crunching)

## IP evaluation

**Purpose.** Assign every IP one category — `attacker`, `bad_crawler`,
`good_crawler` or `regular_user` — from its behaviour. The category drives bans,
banlist exports and the dashboard.

**When.** `analyze-ips` runs every minute and takes up to `tasks.analyze_ips_batch`
IPs (default 2000): those never analysed, then those flagged `need_reevaluation`,
oldest analysis first. `flag-stale-ips` (daily) flags IPs seen within
`retention.non-suspicious` whose last analysis is older than
`retention.re-evaluate-interval`. Manually categorised IPs are never re-flagged.

**Inputs.** The IP's access logs from the last 30 days, at most 10,000 rows.

**Signals.** Each signal is a yes/no flag per category:

| Signal | Measure | Fires when (config) |
|---|---|---|
| Risky methods | share of POST/PUT/DELETE/OPTIONS/PATCH requests | ≥ `analyzer.http_risky_methods_threshold` (0.1) |
| robots.txt violations | share of requests under a `Disallow:` path of Krawl's robots.txt | ≥ `analyzer.violated_robots_threshold` (0.1) |
| Uneven timing | coefficient of variation (std/mean) of gaps between requests in the last `analyzer.uneven_request_timing_time_window_seconds` (300s) | ≥ `analyzer.uneven_request_timing_threshold` (0.5) |
| Many user agents | distinct user agents | ≥ `analyzer.user_agents_used_threshold` (2) |
| Attack URLs | distinct attack types stored for the IP's requests in the window (any field: path, query, body, headers), as detected when each request arrived | ≥ `analyzer.attack_urls_threshold` (1) |

**Scoring.** Each category's score is the sum of the weights of the signals that
fired *for that category*. Default weights (overridable with `analyzer.scoring_weights`
in `config.yaml`):

| Signal | attacker | good_crawler | bad_crawler | regular_user |
|---|---|---|---|---|
| Risky methods | 6 (fires if high) | 1 (fires if **low**) | 2 (fires if high) | 0 |
| robots.txt violations | 4 | 0 | 6 | 0 |
| Uneven timing | 3 | 0 | 0 | 8 |
| Many user agents | 2 | 0 | 6 | 3 |
| Attack URLs | 15 | 0 | 4 | 0 |

The highest score wins. On a tie, the first category in the order attacker,
good_crawler, bad_crawler, regular_user wins.

**Worked example.** An IP sends 40 GETs, 4 POSTs (9% risky), 6 requests under
`/admin` (a `Disallow` path, 14%), with 2 user agents and one `/.env` probe:

- attacker = 4 (robots) + 2 (UAs) + 15 (attack URL) = **21**
- good_crawler = 1 (risky share is low)
- bad_crawler = 6 (robots) + 6 (UAs) = 12
- regular_user = 0

The IP becomes an `attacker`.

**Known limits** (current behaviour, kept as is):

- The risky-method ratio is computed only when the row count exceeds
  `http_risky_methods_threshold` (0.1), so in practice always.
- The `regular_user` "many user agents" flag is never set, so its weight (3) is unused.
- The stored `uneven_request_timing` metric is the mean gap, not the CV that the
  threshold compares.
- A crunched access-log row counts as `hit_count` requests in the ratios, so
  crunching does not move a category (see below).

## Request crunching

**Purpose.** Most stored requests are crawlers following Krawl's own random
homepage links: on the demo instance about 3M IPs, each with a handful of
unique paths like `/Gw2JM958`. The crunch job keeps that history but stores it
compactly, by merging similar non-suspicious requests of an inactive IP into one
row that remembers how many requests it stands for.

**When.** `crunch-access-logs` runs every 5 minutes and takes up to
`tasks.crunch_ips_batch` IPs (default 5000) whose `last_seen` is older than `retention.crunch-after` (7d)
and that have not been crunched since their last activity (`ip_stats.crunched_at`).
IPs with a single request are skipped (nothing to merge), and the most recently
idle IPs go first: the oldest rows are purged by retention soon anyway.
An IP that comes back and goes idle again is crunched again.

**Which rows.** Only non-suspicious, non-honeypot rows that have no uploaded file
and no request asset. Attack evidence is never merged.

**Templates.** Each path is reduced to a shape; the first matching rule wins:

| Rule | Example | Template |
|---|---|---|
| Whole path is a Krawl trap link: one segment, `links.char_space` only, length within `links.min_length`..`max_length`, and a digit or an uppercase letter after the first character | `/Gw2JM958` | `/{link}` |
| Segment is a UUID | `/u/550e8400-e29b-41d4-a716-446655440000` | `/u/{uuid}` |
| Segment is all digits | `/post/1234` | `/post/{num}` |
| Segment is ≥ 8 hex characters with a digit | `/c/9f86d081a2` | `/c/{hex}` |
| Segment is ≥ 8 `[A-Za-z0-9]` with a digit and a letter, no `_`/`-` and no run of 5+ lowercase letters (extension kept) | `/f/aB3xK9pQ.js` | `/f/{rand}.js` |
| Anything else, including readable names with digits | `/wp-login.php`, `/login`, `/.ssh/id_ed25519`, `/wp2shell_opt_woocommerce_stripe_settings` | unchanged |
| Query values | `?q=foo&page=2` | `?q={v}&page={v}` |

The "visibly random" requirement on trap links exists because Krawl's minimum
link length (5) also fits words like `/login` and `/admin`. On the demo data it
caught 98.7% of trap links and matched none of the real top paths. The 1.3% it
misses (all-lowercase, like `/kpjud`) simply stay uncrunched.

**Merge.** Rows of one IP sharing `(method, template, target host, user agent)`
become one row: the lowest id is kept, `path` becomes the template, `hit_count`
is the sum, `timestamp` is the newest, and `path_samples` keeps up to 3 real
example paths. A group of a single row is left untouched: merging it would
save nothing and only hide the real path. The user agent is part of the key because IP evaluation counts
distinct user agents. Paths under a robots.txt `Disallow` prefix are never
templated (IP evaluation scores them by prefix), and neither is a path whose
template would not fit the path column.

**Example.**

    GET /dasidaniodna, GET /daefndisjd, GET /sdleijfwmi, GET /test   (one user agent)
      → GET /{link}  ×3  (e.g. /dasidaniodna, /daefndisjd, /sdleijfwmi)
      → GET /test    ×1

**Effects elsewhere.**
- Top paths, top user agents and target-host counts sum `hit_count`, so totals are unchanged.
- Unique-path counts drop, because templates collapse random paths.
- IP evaluation weights rows by `hit_count`, so a crunched IP keeps its category.
- Retention purges a crunched row once its newest request is older than `retention.non-suspicious`.

**Known limits.**
- Merging is per IP. Dormant crawlers usually have only 1–2 rows each, so the
  saving is concentrated on heavy single-IP crawlers. Lowering
  `retention.non-suspicious` is the bigger lever for table size.
- Ratios can still shift slightly for long-lived groups: IP evaluation reads 30
  days / 10,000 rows of history, and a crunched row carries its newest timestamp
  and its full hit count.
