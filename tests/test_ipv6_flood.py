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


if __name__ == "__main__":
    test_defer_persist()
    test_geo_shared()
