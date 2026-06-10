"""
Event-driven metric counters backed by the cache layer.

Counters live under the krawl:counter: prefix so they survive the krawl:cache:*
flush that runs on every pod startup (see dashboard_cache.flush_all). In
scalable mode they are Redis keys (atomic INCRBY, shared across pods); in
standalone mode they are a locked in-memory dict. Values feed Prometheus gauges
(set at scrape time) and the dashboard's aggregate counts.

Encoding: a labeled counter is stored as "metric|label"; an unlabeled one as
"metric". Distinctness sets (e.g. seen request paths) live under
krawl:counter:set:<name>.
"""

import threading
from collections.abc import Iterable

from dashboard_cache import get_backend, get_redis_client

_COUNTER_PREFIX = "krawl:counter:"
_SET_PREFIX = "krawl:counter:set:"
_SEED_MARKER = "krawl:counter:_seeded"

_lock = threading.Lock()
_counters: dict[str, int] = {}
_sets: dict[str, set] = {}


def _key(metric: str, label: str = "") -> str:
    return f"{metric}|{label}" if label else metric


def _split_key(key: str) -> tuple[str, str]:
    if "|" in key:
        metric, label = key.split("|", 1)
        return metric, label
    return key, ""


def increment(metric: str, label: str = "", amount: int = 1) -> None:
    """Increment a counter by amount (default 1)."""
    if get_backend() == "scalable":
        r = get_redis_client()
        if r is not None:
            r.incrby(f"{_COUNTER_PREFIX}{_key(metric, label)}", amount)
            return
    with _lock:
        k = _key(metric, label)
        _counters[k] = _counters.get(k, 0) + amount


def get(metric: str, label: str = "") -> int:
    """Return the current value of a counter (0 if unset)."""
    if get_backend() == "scalable":
        r = get_redis_client()
        if r is not None:
            raw = r.get(f"{_COUNTER_PREFIX}{_key(metric, label)}")
            return int(raw) if raw else 0
    with _lock:
        return _counters.get(_key(metric, label), 0)


def set_value(metric: str, label: str = "", value: int = 0) -> None:
    """Set a counter to an absolute value (used when seeding from the DB)."""
    if get_backend() == "scalable":
        r = get_redis_client()
        if r is not None:
            r.set(f"{_COUNTER_PREFIX}{_key(metric, label)}", int(value))
            return
    with _lock:
        _counters[_key(metric, label)] = int(value)


def get_many(metrics) -> dict[str, int]:
    """Batch-read unlabeled counters as {metric: value}.

    Scalable: a single Redis MGET (one round-trip instead of one GET each).
    Standalone: locked dict reads.
    """
    metrics = list(metrics)
    if get_backend() == "scalable":
        r = get_redis_client()
        if r is not None:
            if not metrics:
                return {}
            raw = r.mget([f"{_COUNTER_PREFIX}{m}" for m in metrics])
            return {m: (int(v) if v else 0) for m, v in zip(metrics, raw, strict=False)}
    with _lock:
        return {m: _counters.get(m, 0) for m in metrics}


def get_all() -> dict[str, int]:
    """Return all counters as {encoded_key: value}. Excludes distinctness sets."""
    if get_backend() == "scalable":
        r = get_redis_client()
        out: dict[str, int] = {}
        if r is not None:
            keys = []
            cursor = 0
            while True:
                cursor, batch = r.scan(cursor, match=f"{_COUNTER_PREFIX}*", count=200)
                keys.extend(
                    k
                    for k in batch
                    if not k.startswith(_SET_PREFIX) and k != _SEED_MARKER
                )
                if cursor == 0:
                    break
            if keys:
                raw = r.mget(keys)
                out = {
                    k[len(_COUNTER_PREFIX) :]: (int(v) if v else 0)
                    for k, v in zip(keys, raw, strict=False)
                }
        return out
    with _lock:
        return dict(_counters)


def add_to_set(name: str, member: str) -> bool:
    """Add member to a distinctness set. Return True if it was newly added."""
    if get_backend() == "scalable":
        r = get_redis_client()
        if r is not None:
            return r.sadd(f"{_SET_PREFIX}{name}", member) == 1
    with _lock:
        s = _sets.setdefault(name, set())
        if member in s:
            return False
        s.add(member)
        return True


def scard(name: str) -> int:
    """Return the cardinality of a distinctness set."""
    if get_backend() == "scalable":
        r = get_redis_client()
        if r is not None:
            return int(r.scard(f"{_SET_PREFIX}{name}"))
    with _lock:
        return len(_sets.get(name, set()))


def seed_set(name: str, members: Iterable[str]) -> None:
    """Replace a distinctness set's contents (used when seeding from the DB)."""
    members = list(members)
    if get_backend() == "scalable":
        r = get_redis_client()
        if r is not None:
            if members:
                r.sadd(f"{_SET_PREFIX}{name}", *members)
            return
    with _lock:
        _sets[name] = set(members)


def needs_seed() -> bool:
    """
    Decide whether this process should (re)seed the counters.

    Scalable: atomically set a persistent marker only if absent; returns True to
    exactly one pod (the one that just set it), which then owns the one-time
    seed. The marker lives under the non-flushed prefix, so it survives pod
    restarts and only disappears if Redis itself is wiped (in which case
    reseeding is correct).

    Standalone: always True — the in-memory counters are lost on every restart
    and must be re-seeded from the Summary table.
    """
    if get_backend() == "scalable":
        r = get_redis_client()
        if r is not None:
            return bool(r.set(_SEED_MARKER, "1", nx=True))
        return True
    return True


# Heavy aggregates persisted in metrics_summary (and recomputed from SQL).
HEAVY_METRICS = (
    "total_accesses",
    "unique_ips",
    "unique_paths",
    "suspicious_accesses",
    "honeypot_triggered",
    "honeypot_ips",
)

# Cumulative metrics whose true total-ever = count(current rows) + deleted tally.
# Other heavy metrics are preserved by retention (suspicious/honeypot rows are
# never purged), so their current count already equals the cumulative total.
_TALLIED_METRICS = ("total_accesses", "unique_ips")

_RECONCILE_LOCK = "krawl:counter:_reconcile_lock"


def _acquire_reconcile_lock(ttl: int = 600) -> bool:
    """Return True if this process should run the (expensive) full recompute.

    Scalable: a short-lived Redis lock so only one pod recomputes per window.
    Standalone: always True (single process).
    """
    if get_backend() == "scalable":
        r = get_redis_client()
        if r is not None:
            return bool(r.set(_RECONCILE_LOCK, "1", nx=True, ex=ttl))
        return True
    return True


def _recompute_heavy(db) -> None:
    """Recompute heavy counters as cumulative absolutes from the DB + tallies.

    For tallied metrics, cumulative = count(current rows) + deleted tally, so
    they stay "total ever observed" even after retention purges benign rows.
    The seen-paths set is left untouched (append-only distinct-ever); we only
    keep the unique_paths counter aligned to its cardinality.
    """
    counts = db._compute_dashboard_counts_sql()
    tallies = db.get_deleted_tallies()
    for metric in HEAVY_METRICS:
        if metric == "unique_paths":
            continue  # backed by the append-only seen-paths set
        base = int(counts.get(metric, 0) or 0)
        if metric in _TALLIED_METRICS:
            base += int(tallies.get(metric, 0) or 0)
        set_value(metric, "", base)
    set_value("unique_paths", "", scard("paths"))
    db.upsert_metrics_summary({(m, ""): get(m) for m in HEAVY_METRICS})


def _recompute_cheap(db) -> None:
    """Recompute cumulative metrics that are cheap and preserved by retention."""
    set_value("credentials_captured", "", db.count_credentials())
    # attack_detections rows are preserved by retention (they hang off suspicious
    # logs), so the current per-type count equals the cumulative total.
    for entry in db.get_attack_types_stats(limit=100).get("attack_types", []):
        set_value("attack_detections", entry["type"], int(entry["count"]))


def bootstrap(db) -> None:
    """
    Seed live counters at startup. Idempotent and safe across pods.

    In scalable mode only the first pod (per needs_seed) seeds; in standalone it
    runs every boot. Heavy aggregates load from the persisted snapshot (fast,
    avoids a full scan on every pod start) or are recomputed from SQL on first
    run. clients_total is NOT seeded here — it is recomputed live at scrape time.
    """
    if not needs_seed():
        return

    try:
        # Seen-paths distinctness set: rebuild only if absent (e.g. Redis wiped).
        # It is append-only across restarts, so we never shrink it here.
        if scard("paths") == 0:
            seed_set("paths", db.get_distinct_paths())

        heavy = db.get_heavy_summary()
        if heavy:
            for metric, value in heavy.items():
                set_value(metric, "", value)
            # Keep unique_paths at least the cumulative we last persisted, even
            # if the set was rebuilt from a smaller current-distinct after a wipe.
            set_value(
                "unique_paths",
                "",
                max(scard("paths"), int(heavy.get("unique_paths", 0))),
            )
        else:
            _recompute_heavy(db)

        _recompute_cheap(db)
    except Exception:
        # Never block startup on metrics seeding.
        import logging

        logging.getLogger("krawl").exception("metrics_counters.bootstrap failed")


def reconcile(db) -> None:
    """
    Recompute cumulative counters from source, correcting any event-driven drift.

    Called at startup (via bootstrap) and right after each db-retention run — the
    only thing that deletes data. Guarded by a Redis lock so just one pod runs
    the full scan. Does not touch clients_total (recomputed live at scrape).
    """
    if not _acquire_reconcile_lock():
        return
    try:
        _recompute_heavy(db)
        _recompute_cheap(db)
    except Exception:
        import logging

        logging.getLogger("krawl").exception("metrics_counters.reconcile failed")
