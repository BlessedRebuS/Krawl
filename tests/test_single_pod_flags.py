#!/usr/bin/env python3

"""Exactly the right tasks are gated to one pod.

The unflagged four maintain PER-POD state: a blanket gate would silently stop
each pod flushing its own buffers and filling its own in-process caches, which
fails quietly and is very hard to spot in production.

Usage: python tests/test_single_pod_flags.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from apscheduler.schedulers.background import BackgroundScheduler

from tasks_master import TasksMaster

# Global effect: runs once per cluster.
EXPECTED_SINGLE_POD = {
    "analyze-ips",
    "dashboard-warmup",
    "db-retention",
    "dump-krawl-data",
    "fetch-ip-rep",
    "flag-stale-ips",
    "hash-payloads",
    "pre-retention-cleanup",
    "refresh-banlist",     # gated, but followers adopt via on_skip()
    "sync-cloudflare",
}

# Per-pod state: must run everywhere, every time.
EXPECTED_EVERY_POD = {
    "flush-access-logs",   # drains this pod's access-log write buffer
    "metrics-flush",       # flushes this pod's counters
    "refresh-ban-cache",   # fills this pod's banned-IP frozenset
    "purge",               # disabled; only ever run from the maintenance panel
}


def test_flags_match_intent():
    tasks = TasksMaster(BackgroundScheduler()).tasks
    flagged = {t["name"] for t in tasks if t.get("single_pod")}
    unflagged = {t["name"] for t in tasks if not t.get("single_pod")}

    missing = EXPECTED_SINGLE_POD - flagged
    assert not missing, f"these should be gated to one pod: {sorted(missing)}"

    wrongly_gated = EXPECTED_EVERY_POD & flagged
    assert not wrongly_gated, (
        f"these keep per-pod state and must run everywhere: {sorted(wrongly_gated)}"
    )

    unexpected = flagged - EXPECTED_SINGLE_POD
    assert not unexpected, (
        f"new gated tasks -- confirm they hold no per-pod state: {sorted(unexpected)}"
    )

    unaccounted = unflagged - EXPECTED_EVERY_POD
    assert not unaccounted, (
        f"new ungated tasks -- confirm they are safe to run N times: {sorted(unaccounted)}"
    )


if __name__ == "__main__":
    test_flags_match_intent()
    print("PASS: single_pod flags")
