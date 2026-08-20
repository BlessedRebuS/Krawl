#!/usr/bin/env python3

"""
Dashboard session tokens and bruteforce counters.

Redis in scalable mode, so every replica sees the same sessions and the same
lockout; a process-local dict in standalone. Holding these per-process meant a
cookie issued by one pod was unknown to the next, and the 5-attempt lockout
applied per pod rather than per attacker.

Both kinds of entry expire, which also keeps the standalone dicts from growing
for the lifetime of the process.
"""

import json
import threading
import time

from dashboard_cache import get_backend, get_redis_client

_SESSION_PREFIX = "krawl:auth:session:"
_ATTEMPT_PREFIX = "krawl:auth:attempts:"

SESSION_TTL = 12 * 3600
ATTEMPT_TTL = 3600

_lock = threading.Lock()
_sessions: dict[str, float] = {}  # token -> expires_at
_attempts: dict[str, tuple[dict, float]] = {}  # ip -> (record, expires_at)


def _redis():
    """Return the Redis client when scalable mode is active, else None."""
    return get_redis_client() if get_backend() == "scalable" else None


def create_session(token: str) -> None:
    """Register a new authenticated session."""
    r = _redis()
    if r is not None:
        r.setex(f"{_SESSION_PREFIX}{token}", SESSION_TTL, "1")
        return
    with _lock:
        _sessions[token] = time.time() + SESSION_TTL


def is_valid_session(token: str | None) -> bool:
    """True if the token identifies a live session."""
    if not token:
        return False
    r = _redis()
    if r is not None:
        return bool(r.exists(f"{_SESSION_PREFIX}{token}"))
    with _lock:
        expires = _sessions.get(token)
        if expires is None:
            return False
        if expires < time.time():
            del _sessions[token]
            return False
        return True


def destroy_session(token: str | None) -> None:
    """Invalidate a session (logout)."""
    if not token:
        return
    r = _redis()
    if r is not None:
        r.delete(f"{_SESSION_PREFIX}{token}")
        return
    with _lock:
        _sessions.pop(token, None)


def get_attempts(ip: str) -> dict | None:
    """Return the failed-attempt record for an IP, if any."""
    r = _redis()
    if r is not None:
        raw = r.get(f"{_ATTEMPT_PREFIX}{ip}")
        return json.loads(raw) if raw else None
    with _lock:
        entry = _attempts.get(ip)
        if entry is None:
            return None
        record, expires = entry
        if expires < time.time():
            del _attempts[ip]
            return None
        return record


def save_attempts(ip: str, record: dict) -> None:
    """Persist the failed-attempt record for an IP."""
    ttl = max(ATTEMPT_TTL, int(record.get("locked_until", 0) - time.time()) + 60)
    r = _redis()
    if r is not None:
        r.setex(f"{_ATTEMPT_PREFIX}{ip}", ttl, json.dumps(record))
        return
    with _lock:
        _attempts[ip] = (record, time.time() + ttl)


def clear_attempts(ip: str) -> None:
    """Drop an IP's failed-attempt record (successful login)."""
    r = _redis()
    if r is not None:
        r.delete(f"{_ATTEMPT_PREFIX}{ip}")
        return
    with _lock:
        _attempts.pop(ip, None)


def count_locked() -> int:
    """IPs currently serving a bruteforce lockout (for metrics)."""
    now = time.time()
    r = _redis()
    if r is not None:
        locked = 0
        for key in r.scan_iter(match=f"{_ATTEMPT_PREFIX}*", count=200):
            raw = r.get(key)
            if raw and json.loads(raw).get("locked_until", 0) > now:
                locked += 1
        return locked
    with _lock:
        return sum(
            1
            for record, expires in _attempts.values()
            if expires > now and record.get("locked_until", 0) > now
        )
