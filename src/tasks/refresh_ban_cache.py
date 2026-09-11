#!/usr/bin/env python3

"""Keep the in-process banned-IP set current.

Cheap enough to run often: one indexed query returning one column, against a
set that is small by construction. The interval is the window in which a ban
applied by *another* replica is not yet enforced here; bans applied by this
process take effect immediately via ban_cache.add().
"""

import ban_cache
from config import get_config
from logger import get_app_logger

TASK_CONFIG = {
    "name": "refresh-ban-cache",
    "enabled": True,
    # The set answers "not banned" authoritatively, so it must be loaded before
    # the fast path is used. It refuses to answer until this has run once.
    "run_when_loaded": True,
    "interval_seconds": 30,
}


def main():
    count = ban_cache.refresh(
        ban_duration_seconds=get_config().ban_duration_seconds,
    )
    get_app_logger().debug(f"[RefreshBanCache] {count} banned IPs held in memory")
