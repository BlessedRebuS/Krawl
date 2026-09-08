#!/usr/bin/env python3

"""Checks for the in-memory banned-IP fast path.

The fast path skips a database read on every request, so the property that
matters is one-sided: it may never answer "not banned" for an IP that is. Each
check below is a way that could break.

Usage: python tests/test_ban_cache.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import ban_cache


class FakeRepo:
    """Stands in for ip_stats.get_banned_ips."""

    def __init__(self, ips):
        self.ips = ips
        self.calls = 0

    def get_banned_ips(self, ban_duration_seconds, limit=200_000):
        self.calls += 1
        return list(self.ips)[:limit]


class FakeDB:
    def __init__(self, ips):
        self.ip_stats = FakeRepo(ips)


def reset():
    ban_cache._banned = frozenset()
    ban_cache._ready = False


def test_not_ready_before_first_refresh():
    """An empty set must not be mistaken for "nobody is banned"."""
    reset()
    assert ban_cache.is_ready() is False, (
        "the fast path must refuse to answer until the set is loaded, "
        "or every banned IP is served during startup"
    )


def test_refresh_loads_and_answers():
    reset()
    db = FakeDB(["203.0.113.7", "198.51.100.2"])
    assert ban_cache.refresh(db=db) == 2
    assert ban_cache.is_ready() is True
    assert ban_cache.is_banned("203.0.113.7") is True
    assert ban_cache.is_banned("192.0.2.1") is False


def test_local_ban_takes_effect_immediately():
    """A ban this process applies must not wait for the next refresh."""
    reset()
    ban_cache.refresh(db=FakeDB([]))
    assert ban_cache.is_banned("203.0.113.9") is False
    ban_cache.add("203.0.113.9")
    assert ban_cache.is_banned("203.0.113.9") is True


def test_overflow_disables_the_fast_path():
    """Truncating the set would let the IPs past the cap through, so past the
    cap it stops answering instead."""
    reset()
    ban_cache.refresh(db=FakeDB([]))
    assert ban_cache.is_ready() is True

    too_many = [f"10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}" for i in range(50)]
    original = ban_cache.MAX_BANNED_IPS
    try:
        ban_cache.MAX_BANNED_IPS = 10
        assert ban_cache.refresh(db=FakeDB(too_many)) == 0
        assert ban_cache.is_ready() is False, (
            "an overflowed set must fall back to the database, not answer "
            "from a truncated one"
        )
    finally:
        ban_cache.MAX_BANNED_IPS = original


def test_lookup_is_sanitized():
    """The set holds IPs as the database stores them; the middleware passes a
    header value. Comparing the two raw would miss a banned IP."""
    reset()
    from sanitizer import sanitize_ip

    raw = "  203.0.113.7  "
    stored = sanitize_ip(raw)
    ban_cache.refresh(db=FakeDB([stored]))
    assert ban_cache.is_banned(raw) is True, (
        f"{raw!r} must match its stored form {stored!r}"
    )


if __name__ == "__main__":
    test_not_ready_before_first_refresh()
    print("OK: no authoritative answers before the first refresh")
    test_refresh_loads_and_answers()
    print("OK: refresh loads the set and answers membership")
    test_local_ban_takes_effect_immediately()
    print("OK: a locally applied ban is enforced without waiting for a refresh")
    test_overflow_disables_the_fast_path()
    print("OK: past the cap the fast path disables itself")
    test_lookup_is_sanitized()
    print("OK: lookups are sanitized to the stored form")
    reset()
