# tasks/dashboard_warmup.py

"""
Pre-computes all Overview tab data and stores it in the cache.
Lets the dashboard respond instantly without hitting the database.
"""

import time
from logger import get_app_logger
from config import get_config
from database import get_database
from dashboard_cache import set_cached, set_cached_table

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

        def _timed(label, fn):
            t0 = time.monotonic()
            result = fn()
            elapsed = time.monotonic() - t0
            app_logger.info(f"[Background Task] {task_name} {label}: {elapsed:.2f}s")
            return result

        # --- Server-rendered data (stats cards + suspicious table) ---
        stats = _timed("get_dashboard_counts", db.get_dashboard_counts)

        # credential_count is derived from the full credentials query below
        # (avoids a redundant DB call)

        suspicious = _timed(
            "get_recent_suspicious", lambda: db.get_recent_suspicious(limit=10)
        )

        # --- HTMX Overview tables (first page, default sort) ---
        top_ua = _timed(
            "get_top_user_agents_paginated",
            lambda: db.get_top_user_agents_paginated(page=1, page_size=5),
        )
        top_paths = _timed(
            "get_top_paths_paginated",
            lambda: db.get_top_paths_paginated(page=1, page_size=5),
        )

        # --- Map data (default: top 1000 IPs by total_requests) ---
        # Also used to derive top_ips (first 8), avoiding a redundant DB query
        map_ips = _timed(
            "get_all_ips_paginated",
            lambda: db.get_all_ips_paginated(
                page=1, page_size=1000, sort_by="total_requests", sort_order="desc"
            ),
        )

        # Derive top_ips from map_ips (both sorted by total_requests desc)
        top_ips_from_map = map_ips.get("ips", [])[:8]
        top_ips = {
            "ips": [
                {
                    "ip": ip["ip"],
                    "count": ip["total_requests"],
                    "category": ip.get("category") or "unknown",
                }
                for ip in top_ips_from_map
            ],
            "pagination": {
                "page": 1,
                "page_size": 8,
                "total": map_ips.get("pagination", {}).get("total", 0),
                "total_pages": max(
                    1,
                    (map_ips.get("pagination", {}).get("total", 0) + 7) // 8,
                ),
            },
        }

        # --- Attack panel data (first page, default sort) ---
        attacks = _timed(
            "get_attack_types_paginated",
            lambda: db.get_attack_types_paginated(
                page=1, page_size=15, sort_by="timestamp", sort_order="desc"
            ),
        )
        attackers = _timed(
            "get_attackers_paginated",
            lambda: db.get_attackers_paginated(
                page=1, page_size=10, sort_by="total_requests", sort_order="desc"
            ),
        )
        credentials = _timed(
            "get_credentials_paginated",
            lambda: db.get_credentials_paginated(
                page=1, page_size=5, sort_by="timestamp", sort_order="desc"
            ),
        )
        honeypot = _timed(
            "get_honeypot_paginated",
            lambda: db.get_honeypot_paginated(
                page=1, page_size=5, sort_by="count", sort_order="desc"
            ),
        )
        attack_trends = _timed(
            "get_attack_types_daily",
            lambda: db.get_attack_types_daily(limit=10, days=7, offset_days=0),
        )

        # Derive credential count from the full credentials query
        stats["credential_count"] = credentials.get("pagination", {}).get("total", 0)

        # Store everything in the cache (overwrites previous values)
        set_cached("stats", stats)
        set_cached("suspicious", suspicious)
        set_cached("top_ips", top_ips)
        set_cached("top_ua", top_ua)
        set_cached("top_paths", top_paths)
        set_cached("map_ips", map_ips)

        # Attack panel table caches (used by HTMX and API endpoints)
        set_cached_table("attacks:1:timestamp:desc::", attacks)
        set_cached_table("attackers:1:total_requests:desc", attackers)
        set_cached_table("credentials:1:timestamp:desc", credentials)
        set_cached_table("honeypot:1:count:desc", honeypot)
        set_cached_table("api:attack_daily:10:7:0", attack_trends)

        app_logger.info(f"[Background Task] {task_name} cache refreshed successfully.")

    except Exception as e:
        app_logger.error(f"[Background Task] {task_name} failed: {e}")
