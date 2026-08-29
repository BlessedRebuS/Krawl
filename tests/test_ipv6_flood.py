#!/usr/bin/env python3

"""
Checks for the two IPv6 flood defences.

Background: a rotating proxy pool used one IPv6 address per request — 24,500
addresses from a single /32, every one with total_requests = 1. That filled 42%
of ip_stats with rows that would never be seen again, and queued a geolocation
lookup for each.

1. ip_utils.defer_persist: an IPv6 address earns its row on the second
   sighting. IPv4 and suspicious traffic are never deferred.
2. geo_utils.extract_geolocation_shared: one lookup answers for a whole /48.
3. ip_utils.is_ignored_ip honours the `ipv6.ignore` policy, and the standalone
   first-sighting ledger stays bounded under a flood.
4. The access-log write buffer is capped by bytes, not just by row count.

Usage: python tests/test_ipv6_flood.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import geo_utils
import ip_utils

V6 = "2a13:f41:90a8:10ba:3385:f289:6613:e84d"
V6_SIBLING = "2a13:f41:90a8:ffff:1111:2222:3333:4444"  # same /48
V6_OTHER = "2a13:f41:a171:fadb:673b:3781:bc1:4a74"  # different /48
V4 = "203.0.113.7"


def test_defer_persist():
    ip_utils._seen.clear()

    # The flood: first sighting of an ordinary IPv6 address is not persisted.
    assert ip_utils.defer_persist(V6, False, False) is True
    # It came back — now it earns a row.
    assert ip_utils.defer_persist(V6, False, False) is False

    # IPv4 is never deferred, not even on first sight.
    assert ip_utils.defer_persist(V4, False, False) is False

    # A one-shot attacker is persisted immediately despite being new IPv6.
    ip_utils._seen.clear()
    assert ip_utils.defer_persist(V6_OTHER, True, False) is False
    ip_utils._seen.clear()
    assert ip_utils.defer_persist(V6_OTHER, False, True) is False

    # Expiry: a sighting older than the window does not count as a return visit.
    ip_utils._seen.clear()
    assert ip_utils.seen_before(V6, ttl=0) is False
    assert ip_utils.seen_before(V6, ttl=0) is False, "expired entry must not count"

    print("OK: IPv6 deferred until second sighting; IPv4 and suspicious exempt")


def test_geo_shared():
    geo_utils._PREFIX_GEO.clear()
    calls = []

    def fake_lookup(ip):
        calls.append(ip)
        return {"city": "Frankfurt", "latitude": 50.1, "longitude": 8.7, "reverse": ip}

    original = geo_utils.extract_geolocation_from_ip
    geo_utils.extract_geolocation_from_ip = fake_lookup
    try:
        a = geo_utils.extract_geolocation_shared(V6)
        b = geo_utils.extract_geolocation_shared(V6_SIBLING)
        assert calls == [V6], f"a /48 must cost one lookup, got {calls}"
        assert b["latitude"] == a["latitude"]
        # Reverse DNS is per-address, so it must not be copied to a sibling.
        assert b["reverse"] is None, f"reverse must not be shared, got {b['reverse']}"

        # A different /48 is a different network: it costs its own lookup.
        geo_utils.extract_geolocation_shared(V6_OTHER)
        assert calls == [V6, V6_OTHER], f"distinct /48s must not share, got {calls}"

        # IPv4 never shares.
        geo_utils.extract_geolocation_shared(V4)
        geo_utils.extract_geolocation_shared(V4)
        assert calls.count(V4) == 2, "IPv4 must not be cached by prefix"

        # A failed lookup must not poison the /48.
        geo_utils._PREFIX_GEO.clear()
        geo_utils.extract_geolocation_from_ip = lambda ip: None
        assert geo_utils.extract_geolocation_shared(V6) is None
        assert geo_utils._PREFIX_GEO == {}, "failures must not be cached"
    finally:
        geo_utils.extract_geolocation_from_ip = original

    print("OK: one geolocation lookup per /48, failures and IPv4 excluded")


def test_ignore_ipv6_policy():
    """`ipv6.ignore` must drop IPv6 wholesale, and must not leak into callers
    that pass the flag explicitly (the startup purge)."""
    entries = ["127.0.0.0/8"]

    # Policy off: IPv6 is ordinary traffic.
    assert ip_utils.is_ignored_ip(V6, entries, ignore_ipv6=False) is False
    assert ip_utils.is_ignored_ip(V4, entries, ignore_ipv6=False) is False

    # Policy on: every IPv6 address is ignored, IPv4 is untouched.
    assert ip_utils.is_ignored_ip(V6, entries, ignore_ipv6=True) is True
    assert ip_utils.is_ignored_ip(V6_OTHER, entries, ignore_ipv6=True) is True
    assert ip_utils.is_ignored_ip(V4, entries, ignore_ipv6=True) is False

    # The explicit list still applies regardless of the policy.
    assert ip_utils.is_ignored_ip("127.0.0.1", entries, ignore_ipv6=False) is True

    # Malformed input stays ignorable (pre-existing guard).
    assert ip_utils.is_ignored_ip("not-an-ip", entries, ignore_ipv6=False) is True

    print("OK: ipv6.ignore drops all IPv6, leaves IPv4 and the explicit list alone")


def test_seen_ledger_is_bounded():
    """The standalone ledger must not grow without bound.

    This is the failure mode the ledger itself introduced: under a flood it
    holds one entry per address for the whole TTL window.
    """
    ip_utils._seen.clear()
    try:
        for i in range(ip_utils._MAX_SEEN + 100):
            ip_utils.seen_before(f"2001:db8::{i:x}", ttl=3600)
        size = ip_utils.get_seen_ledger_size()
        assert size <= ip_utils._MAX_SEEN, (
            f"ledger grew to {size}, cap is {ip_utils._MAX_SEEN}"
        )
    finally:
        ip_utils._seen.clear()

    print(f"OK: first-sighting ledger stays at or below {ip_utils._MAX_SEEN} entries")


def test_write_buffer_byte_cap():
    """A row count is not a memory bound: entries carry up to 16 KiB of
    raw_request, so the buffer must evict on bytes too."""
    import database.core as core

    core._write_buffer.clear()
    core._buffer_bytes = 0
    core._dropped_rows = 0

    big = "x" * 16384  # MAX_RAW_REQUEST, the worst case per entry
    # Enough entries to blow the byte budget well before the 50k row cap.
    n = (core._MAX_BUFFER_BYTES // len(big)) + 500
    for i in range(n):
        core._buffer_access_log_entry(
            ip=f"2001:db8::{i:x}", path="/wp-login.php", raw_request=big
        )

    assert core.get_write_buffer_bytes() <= core._MAX_BUFFER_BYTES, (
        f"buffer held {core.get_write_buffer_bytes()} bytes, "
        f"budget is {core._MAX_BUFFER_BYTES}"
    )
    assert len(core._write_buffer) < core._MAX_BUFFER_ROWS, (
        "byte budget must bite before the row cap for large entries"
    )
    assert core.get_dropped_rows() > 0, "evictions must be counted, not silent"

    # The accounting must survive a drain: bytes go down with the rows.
    before = core.get_write_buffer_bytes()
    popped = core.DatabaseManager._pop_batch(None, 10)
    assert len(popped) == 10
    assert core.get_write_buffer_bytes() < before, "draining must release bytes"

    core._write_buffer.clear()
    core._buffer_bytes = 0
    print(
        f"OK: write buffer capped at {core._MAX_BUFFER_BYTES // (1024 * 1024)} MiB, "
        "evictions counted, drain releases bytes"
    )


def test_paths_set_is_bounded():
    """The standalone distinctness set is append-only; it needs a ceiling."""
    import metrics_counters as mc

    mc._sets.clear()
    try:
        for i in range(mc._MAX_SET_ENTRIES + 200):
            mc.add_to_set("paths", f"/attack-{i}")
        size = mc.get_local_set_size("paths")
        assert size <= mc._MAX_SET_ENTRIES, f"set grew to {size}"
        # Past the cap, add_to_set reports "not new" rather than growing.
        assert mc.add_to_set("paths", "/brand-new-path") is False
    finally:
        mc._sets.clear()

    print(f"OK: distinct-paths set stays at or below {mc._MAX_SET_ENTRIES} entries")


if __name__ == "__main__":
    test_defer_persist()
    test_geo_shared()
    test_ignore_ipv6_policy()
    test_seen_ledger_is_bounded()
    test_write_buffer_byte_cap()
    test_paths_set_is_bounded()
