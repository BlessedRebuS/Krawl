# Retention

Every window that deletes or rewrites stored data lives in one config section.
Durations are `<number><unit>`: `h` hours, `d` days, `w` weeks, `m` 30-day months,
`y` 365-day years. A bare number means days.

```yaml
retention:
  non-suspicious: 30d
  recheck-suspicious: 30d
  re-evaluate-interval: 5d
  crunch-after: 7d
  overall: null
```

| Key | Env var | Job | What happens |
|---|---|---|---|
| `non-suspicious` | `KRAWL_RETENTION_NON_SUSPICIOUS` | `db-retention`, daily 09:00 | Deletes non-suspicious, non-honeypot access logs older than this, with their detections and request assets; `ip_stats` rows of IPs with no suspicious history and `last_seen` older than this; and their category history. Orphaned captured files and campaign clusters go with them. |
| `recheck-suspicious` | `KRAWL_RETENTION_RECHECK_SUSPICIOUS` | `pre-retention-cleanup`, daily 08:30 | Re-runs the URL and user-agent rules on suspicious logs older than this, and unflags the ones that no longer match so `db-retention` can purge them. Logs with body-only detections, uploaded files or request assets are never unflagged. |
| `re-evaluate-interval` | `KRAWL_RETENTION_REEVALUATE_INTERVAL` | `flag-stale-ips`, daily 08:00 | Flags IPs seen within `non-suspicious` whose last analysis is older than this; `analyze-ips` re-scores them. |
| `crunch-after` | `KRAWL_RETENTION_CRUNCH_AFTER` | `crunch-access-logs`, hourly | Merges similar non-suspicious requests of IPs inactive this long into one row with a hit count. See [Algorithms](algorithms.md#request-crunching). |
| `overall` | `KRAWL_RETENTION_OVERALL` | `db-retention` | **Off by default.** When set, deletes *everything* older than this, attack evidence included: access logs, detections, credentials, IP stats and category history. |

Precedence: `KRAWL_RETENTION_*` env vars, then `KRAWL_DATABASE_RETENTION_DAYS`
(deprecated), then `retention.*` in config.yaml, then `database.retention_days`
(deprecated), then the defaults above. The deprecated keys only feed
`non-suspicious` and `recheck-suspicious`.

Not retention, and configured elsewhere: cache lifetimes (`redis.*_ttl`) and ban
windows (`crawl.ban_duration_seconds`).
