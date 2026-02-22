#!/usr/bin/env python3

"""
Memory cleanup task for Krawl honeypot.

NOTE: This task is no longer needed. Ban/rate-limit state has been moved from
in-memory ip_page_visits dict to the ip_stats DB table, eliminating unbounded
memory growth. Kept disabled for reference.
"""

from logger import get_app_logger

# ----------------------
# TASK CONFIG
# ----------------------

TASK_CONFIG = {
    "name": "memory-cleanup",
    "cron": "*/5 * * * *",
    "enabled": False,
    "run_when_loaded": False,
}

app_logger = get_app_logger()


def main():
    app_logger.debug("memory-cleanup task is disabled (ban state now in DB)")
