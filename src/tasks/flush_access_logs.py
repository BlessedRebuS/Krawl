#!/usr/bin/env python3

"""
Flush buffered access-log entries to the database in bulk.

In scalable mode, individual access-log INSERTs are deferred into an
in-memory buffer to avoid per-request network round-trips to PostgreSQL.
This task drains the buffer every few seconds and batch-inserts the rows.
"""

from config import get_config
from logger import get_app_logger

app_logger = get_app_logger()

# ----------------------
# TASK CONFIG
# ----------------------
# Only enable in scalable mode (buffered writes require PostgreSQL)
_config = get_config()
TASK_CONFIG = {
    "name": "flush-access-logs",
    "cron": "*/1 * * * *",  # Cron is coarse; the real interval is the 30s trigger below
    "enabled": _config.mode == "scalable",
    "run_when_loaded": False,
    "interval_seconds": 30,  # Override cron with a fixed interval
}


# ----------------------
# TASK LOGIC
# ----------------------
def main():
    from database import get_database, get_write_buffer_size

    buf_size = get_write_buffer_size()
    if buf_size == 0:
        return

    db = get_database()
    flushed = db.flush_access_log_buffer()

    if flushed > 0:
        remaining = get_write_buffer_size()
        app_logger.debug(
            f"[flush-access-logs] Flushed {flushed} entries"
            + (f" ({remaining} remaining)" if remaining else "")
        )
