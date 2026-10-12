#!/usr/bin/env python3

"""In-process set of banned IPs, so the per-request ban check skips the DB.

Same shape as banlist_sync, read one line apart in the middleware.

Must never be missing a banned IP or the fast path lets one through, so it is
a superset: force bans included, ban expiry left to get_ban_info.
"""

import threading

from logger import get_app_logger
from sanitizer import sanitize_ip

# ponytail: a flood can ban more IPs than we want resident. Past the cap the
# fast path turns itself off rather than answer from a truncated set (which
# would let banned IPs through). ~85 bytes per IPv4 string, so the cap is
# ~17 MiB. Raise it if the warning shows up and the pod has the headroom.
MAX_BANNED_IPS = 200_000

_banned: set[str] = set()
_ready = False  # no authoritative answers until the first successful refresh
_lock = threading.Lock()
_generation = 0


def is_ready() -> bool:
    """True when the set may be trusted to answer "not banned".

    False before the first refresh, and after one that overflowed the cap: the
    caller must fall back to querying the database.
    """
    return _ready


def is_banned(ip: str) -> bool:
    """Membership test against the banned set, without copying it.

    Sanitized on the way in: the set holds IPs as the database stores them,
    and comparing a raw header value against those would miss a banned IP.
    """
    with _lock:
        return sanitize_ip(ip) in _banned


def needs_lookup(ip: str) -> bool:
    """Atomically decide whether SQL must verify this address.

    Checking readiness and membership separately can miss an overflow that
    disables the fast path between the two reads.
    """
    with _lock:
        return not _ready or sanitize_ip(ip) in _banned


def add(ip: str) -> None:
    """Record a ban applied by this process, so it takes effect immediately.

    Without this a freshly banned client keeps being served until the next
    refresh. Other replicas still wait for theirs.
    """
    global _ready, _generation
    safe = sanitize_ip(ip)
    with _lock:
        _generation += 1
        if len(_banned) >= MAX_BANNED_IPS and safe not in _banned:
            _ready = False
            return
        _banned.add(safe)


def refresh(db=None, ban_duration_seconds: int = 600) -> int:
    """Reload the banned set from the database. Returns the number held."""
    global _banned, _ready

    if db is None:
        from database import get_database

        db = get_database()

    with _lock:
        generation = _generation
    ips = db.ip_stats.get_banned_ips(ban_duration_seconds, limit=MAX_BANNED_IPS + 1)

    if len(ips) > MAX_BANNED_IPS:
        with _lock:
            _ready = False
        get_app_logger().warning(
            f"[BanCache] {len(ips)}+ banned IPs exceeds the {MAX_BANNED_IPS} cap; "
            "falling back to per-request database lookups"
        )
        return 0

    # A local ban arriving during the query may not be in its snapshot. Keep
    # the existing set and fall back to SQL until a quiet refresh succeeds.
    with _lock:
        if generation != _generation:
            _ready = False
            return len(_banned)
        _banned = set(ips)
        _ready = True
    return len(_banned)
