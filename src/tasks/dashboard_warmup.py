# tasks/dashboard_warmup.py

"""
Pre-computes all Overview tab data and stores it in the in-memory cache.
This keeps SQLite page buffers warm and lets the dashboard respond instantly.
"""

from logger import get_app_logger
from config import get_config
from database import get_database
from dashboard_cache import set_cached

app_logger = get_app_logger()

# ----------------------
# TASK CONFIG
# ----------------------
TASK_CONFIG = {
    "name": "dashboard-warmup",
    "cron": "*/5 * * * *",
    "enabled": True,
    "run_when_loaded": True,
}


# ----------------------
# TASK LOGIC
# ----------------------
def main():
    """
    Refresh the in-memory dashboard cache with current Overview data.
    TasksMaster will call this function based on the cron schedule.
    """
    task_name = TASK_CONFIG.get("name")

    config = get_config()
    if not config.dashboard_cache_warmup:
        app_logger.info(
            f"[Background Task] {task_name} skipped (cache_warmup disabled in config)."
        )
        return

    app_logger.info(f"[Background Task] {task_name} starting...")

    try:
        db = get_database()

        # --- Server-rendered data (stats cards + suspicious table) ---
        stats = db.get_dashboard_counts()

        cred_result = db.get_credentials_paginated(page=1, page_size=1)
        stats["credential_count"] = cred_result["pagination"]["total"]

        suspicious = db.get_recent_suspicious(limit=10)

        # --- HTMX Overview tables (first page, default sort) ---
        top_ips = db.get_top_ips_paginated(page=1, page_size=8)
        top_ua = db.get_top_user_agents_paginated(page=1, page_size=5)
        top_paths = db.get_top_paths_paginated(page=1, page_size=5)

        # --- Map data (default: top 100 IPs by total_requests) ---
        map_ips = db.get_all_ips_paginated(
            page=1, page_size=100, sort_by="total_requests", sort_order="desc"
        )

        # Store everything in the cache (overwrites previous values)
        set_cached("stats", stats)
        set_cached("suspicious", suspicious)
        set_cached("top_ips", top_ips)
        set_cached("top_ua", top_ua)
        set_cached("top_paths", top_paths)
        set_cached("map_ips", map_ips)

        app_logger.info(f"[Background Task] {task_name} cache refreshed successfully.")

    except Exception as e:
        app_logger.error(f"[Background Task] {task_name} failed: {e}")
