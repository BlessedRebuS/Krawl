#!/usr/bin/env python3

"""
Memory cleanup task for Krawl honeypot.
Periodically cleans expired bans and stale entries from ip_page_visits.
"""

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
        from tracker import get_tracker

        tracker = get_tracker()
        if not tracker:
            app_logger.warning("Tracker not initialized, skipping memory cleanup")
            return

        stats_before = tracker.get_memory_stats()

        tracker.cleanup_memory()

        stats_after = tracker.get_memory_stats()

        visits_reduced = stats_before["ip_page_visits"] - stats_after["ip_page_visits"]

        if visits_reduced > 0:
            app_logger.info(
                f"Memory cleanup: Removed {visits_reduced} stale ip_page_visits entries"
            )

        app_logger.debug(
            f"Memory stats after cleanup: "
            f"ip_page_visits={stats_after['ip_page_visits']}"
        )

    except Exception as e:
        app_logger.error(f"Error during memory cleanup: {e}")
