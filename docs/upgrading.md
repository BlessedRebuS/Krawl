# Upgrading from 2.4 to 3.0

Krawl 3.0 upgrades a 2.4 database in place: start the new image on the same
SQLite file or PostgreSQL database. Back it up first; see [Backups](backups.md).

## Breaking changes

### wordlists.json is gone

Detection now runs on YARA rules, and bait content lives in files under
`responses/`. Krawl ignores a mounted `wordlists.json`, logging one warning at
startup. Move any values you customised into `config.yaml`: see
[Moving from wordlists.json](honeypot.md#moving-from-wordlistsjson).

In Helm, the `wordlists:` values and their ConfigMap are removed. Set the same
keys under `config:`.

### Retention has its own section

`database.retention_days` is replaced by the `retention:` section, with a
separate window for each kind of data:

```yaml
retention:
  non-suspicious: 30d
  recheck-suspicious: 30d
  re-evaluate-interval: 5d
  uninteresting: 7d     # new: random-path crawler GETs
  overall: null         # new: optional hard cap on all data
```

`retention_days` and `KRAWL_DATABASE_RETENTION_DAYS` still set the first two
windows when their own setting is absent, but both are deprecated. See
[Retention](retention.md).

### Cleanup moved off startup

Purging ignored IPs, and IPv6 rows when `ipv6.purge_existing` is on, now runs
in the nightly `db-cleanup` task (03:00), not at startup. Run it sooner from
**Settings → Maintenance**.

### Container and chart defaults

- Helm's pod memory request and limit rose from 64Mi/256Mi to 128Mi/512Mi, and
  pods run as UID 1000.
- uvicorn options moved from the image `CMD` to `entrypoint.sh`, which appends
  them to any command starting with `uvicorn`. Tune them with the
  `KRAWL_UVICORN_*` variables in
  [Configuration](configuration.md#web-server-container-image) rather than a
  custom `command:`.

## What happens on first start

- **Schema.** New columns and indexes are added at startup. On PostgreSQL, the
  large indexes are built afterwards by the `build-online-indexes` task with
  `CREATE INDEX CONCURRENTLY`, so writes are never blocked.
- **Backfills.** Rows stored by 2.4 are processed in batches over the following
  minutes or hours: `extract-request-metadata` (targeted domains, assets),
  `extract-captured-files` (uploaded files) and `hash-payloads` (campaigns).
  The Threats tab and Targeted Domains fill in as they run. Raise the
  `tasks.*_batch` settings if a backlog drains too slowly.
- **Rule names.** Detections stored by 2.4 have no YARA rule name. They show as
  *legacy* in the Rules tab, and count toward a rule only when it is the only
  rule of their attack type.

## New in 3.0

- [YARA detection](detection.md) with over 3,100 bundled rules, a fake reply
  for each kind of attack, and rule uploads from the dashboard.
- Bait pages defined in `responses/manifest.yaml`; see [Honeypot](honeypot.md).
- Dashboard: new Advanced search and Rules tabs, Attack Trends and period
  filters on Attacks, a reworked IP Insight page, and Captured files and Assets
  on Threats. See [Dashboard](dashboard.md).
- Early pruning of uninteresting crawler requests; see
  [How IPs are evaluated](algorithms.md).
- New settings for server and proxy headers, credential fields, error codes,
  scoring weights and task batch sizes; see [Configuration](configuration.md).
