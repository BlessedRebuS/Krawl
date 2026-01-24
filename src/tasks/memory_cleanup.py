#!/usr/bin/env python3

"""
Memory cleanup task for Krawl honeypot.
Periodically trims unbounded in-memory structures to prevent OOM.
"""

from database import get_database
from logger import get_app_logger

# ----------------------
# TASK CONFIG
# ----------------------

TASK_CONFIG = {
    "name": "memory-cleanup",
    "cron": "*/5 * * * *",  # Run every 5 minutes
    "enabled": True,
    "run_when_loaded": False,
}

app_logger = get_app_logger()


def main():
    """
    Clean up in-memory structures in the tracker.
    Called periodically to prevent unbounded memory growth.
    """
    try:
        # Import here to avoid circular imports
        from handler import Handler

        if not Handler.tracker:
            app_logger.warning("Tracker not initialized, skipping memory cleanup")
            return

        # Get memory stats before cleanup
        stats_before = Handler.tracker.get_memory_stats()

        # Run cleanup
        Handler.tracker.cleanup_memory()

        # Get memory stats after cleanup
        stats_after = Handler.tracker.get_memory_stats()

        # Log changes
        access_log_reduced = stats_before["access_log_size"] - stats_after["access_log_size"]
        cred_reduced = stats_before["credential_attempts_size"] - stats_after["credential_attempts_size"]

        if access_log_reduced > 0 or cred_reduced > 0:
            app_logger.info(
                f"Memory cleanup: Trimmed {access_log_reduced} access logs, "
                f"{cred_reduced} credential attempts"
            )

        # Log current memory state for monitoring
        app_logger.debug(
            f"Memory stats after cleanup: "
            f"access_logs={stats_after['access_log_size']}, "
            f"credentials={stats_after['credential_attempts_size']}, "
            f"unique_ips={stats_after['unique_ips_tracked']}"
        )

    except Exception as e:
        app_logger.error(f"Error during memory cleanup: {e}")
