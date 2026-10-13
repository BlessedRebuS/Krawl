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
| Attack URLs | distinct attack-pattern matches on the raw, URL-decoded and double-decoded path | ≥ `analyzer.attack_urls_threshold` (1) |

**Scoring.** Each category's score is the sum of the weights of the signals that
fired *for that category*. Default weights (overridable with `scoring_weights` in
the wordlists):

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

Documented together with the `crunch-access-logs` task.
