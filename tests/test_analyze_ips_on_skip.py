#!/usr/bin/env python3

"""A pod that skips analyze-ips must still refresh its own Prometheus gauges.

These gauges are process-local, so a pod that never sets them exports 0. The
Grafana dashboard reads them with max(), which then returns whichever pod last
held the lease -- a stale high-water mark rather than the current value.

Usage: python tests/test_analyze_ips_on_skip.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import metrics
import tasks.analyze_ips as analyze_ips


def test_on_skip_refreshes_gauges_without_analysing():
    calls = []

    original_refresh_ai = metrics.refresh_ai
    original_refresh_system = metrics.refresh_system
    original_get_database = analyze_ips.get_database

    metrics.refresh_ai = lambda db: calls.append("refresh_ai")
    metrics.refresh_system = lambda db: calls.append("refresh_system")
    analyze_ips.get_database = lambda: object()

    try:
        analyze_ips.on_skip()
    finally:
        metrics.refresh_ai = original_refresh_ai
        metrics.refresh_system = original_refresh_system
        analyze_ips.get_database = original_get_database

    assert calls == ["refresh_ai", "refresh_system"], f"got {calls}"


def test_on_skip_is_discoverable_by_the_guard():
    """The guard finds this hook with getattr(module, 'on_skip', None)."""
    assert callable(getattr(analyze_ips, "on_skip", None))


if __name__ == "__main__":
    test_on_skip_refreshes_gauges_without_analysing()
    test_on_skip_is_discoverable_by_the_guard()
    print("PASS: analyze_ips on_skip")
