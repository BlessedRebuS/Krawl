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
from typing import Dict, Iterable, Tuple

from dashboard_cache import get_backend, get_redis_client

_COUNTER_PREFIX = "krawl:counter:"
_SET_PREFIX = "krawl:counter:set:"
_SEED_MARKER = "krawl:counter:_seeded"

_lock = threading.Lock()
_counters: Dict[str, int] = {}
_sets: Dict[str, set] = {}


def _key(metric: str, label: str = "") -> str:
    return f"{metric}|{label}" if label else metric


def _split_key(key: str) -> Tuple[str, str]:
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


def get_all() -> Dict[str, int]:
    """Return all counters as {encoded_key: value}. Excludes distinctness sets."""
    if get_backend() == "scalable":
        r = get_redis_client()
        out: Dict[str, int] = {}
        if r is not None:
            cursor = 0
            while True:
                cursor, keys = r.scan(
                    cursor, match=f"{_COUNTER_PREFIX}*", count=200
                )
                for full in keys:
                    if full.startswith(_SET_PREFIX) or full == _SEED_MARKER:
                        continue
                    raw = r.get(full)
                    out[full[len(_COUNTER_PREFIX):]] = int(raw) if raw else 0
                if cursor == 0:
                    break
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
