#!/usr/bin/env python3

"""Pod startup must not discard the cluster's shared cache.

In scalable mode krawl:cache:* is shared by every pod. Flushing it on boot means
one pod restarting throws away work the others are still serving, and a
crash-looping pod does it over and over. In standalone the process starts with an
empty dict anyway, so the flush was only ever a no-op there.

Usage: python tests/test_no_startup_flush.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import dashboard_cache


def test_flush_all_is_gone():
    assert not hasattr(dashboard_cache, "flush_all"), (
        "flush_all had one caller (app startup) and wiped the shared cluster cache"
    )


def test_app_does_not_import_a_flush():
    source = (Path(__file__).resolve().parent.parent / "src" / "app.py").read_text()
    assert "flush_all" not in source, "app.py still imports the startup flush"
    assert "flush_cache" not in source, "app.py still calls the startup flush"


def test_cache_still_works_without_it():
    """Deleting the flush must not disturb ordinary cache use."""
    dashboard_cache._backend = "standalone"
    dashboard_cache._redis_client = None
    dashboard_cache.set_cached("probe", {"value": 1})
    assert dashboard_cache.get_cached("probe") == {"value": 1}


if __name__ == "__main__":
    test_flush_all_is_gone()
    test_app_does_not_import_a_flush()
    test_cache_still_works_without_it()
    print("PASS: no startup cache flush")
