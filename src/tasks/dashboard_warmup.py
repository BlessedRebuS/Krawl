# tasks/dashboard_warmup.py

"""
Pre-computes all Overview tab data and stores it in the cache.
Lets the dashboard respond instantly without hitting the database.
"""

import time

import metrics
from config import get_config
from dashboard_cache import set_cached, set_cached_table
from database import get_database
from logger import get_app_logger

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
    warmup_pages = config.dashboard_warmup_pages
    warmup_aggregation = config.dashboard_warmup_aggregation
    min_count = config.dashboard_top_n_min_count
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
            metrics.observe_warmup_step(label, elapsed)
            return result

        def _warm_pages(
            label,
            fetch_bulk,
            rows_key,
            total_key,
            page_size,
            key_fmt,
            clamp_pages=False,
        ):
            """Warm the first `warmup_pages` cache pages of a paginated table
            with a SINGLE query instead of one query per page.

            `fetch_bulk` runs one paginated call sized for all pages at once;
            the rows are then sliced into per-page cache entries whose shape is
            byte-identical to what the individual per-page query produced, so
            dashboard reads are unaffected. `clamp_pages` mirrors the source
            method's total_pages formula (honeypot clamps to a minimum of 1;
            the others report 0 when empty). Returns the bulk result so callers
            can derive totals.
            """
            bulk = _timed(label, fetch_bulk)
            rows = bulk.get(rows_key, [])
            total = bulk.get("pagination", {}).get(total_key, 0)
            total_pages = (total + page_size - 1) // page_size
            if clamp_pages:
                total_pages = max(1, total_pages)
            for p in range(1, warmup_pages + 1):
                chunk = rows[(p - 1) * page_size : p * page_size]
                set_cached_table(
                    key_fmt.format(p=p),
                    {
                        rows_key: chunk,
                        "pagination": {
                            "page": p,
                            "page_size": page_size,
                            total_key: total,
                            "total_pages": total_pages,
                        },
                    },
                )
            return bulk

        # --- Server-rendered data (stats cards + suspicious table) ---
        stats = _timed("get_dashboard_counts", db.access_logs.get_dashboard_counts)

        # credential_count is derived from the full credentials query below
        # (avoids a redundant DB call)

        suspicious = _timed(
            "get_recent_suspicious",
            lambda: db.access_logs.get_recent_suspicious(limit=10),
        )

        # --- HTMX Overview tables (aggregation or first page, default sort) ---
        if warmup_aggregation:
            top_ua_all = _timed(
                "get_top_ua_all",
                lambda: db.analytics.get_top_user_agents(
                    limit=100_000, min_count=min_count
                ),
            )
            agg_ua = [{"user_agent": ua, "count": c} for ua, c in top_ua_all]
            set_cached("agg:top_ua", agg_ua)
            top_ua = {
                "user_agents": agg_ua[:5],
                "pagination": {
                    "page": 1,
                    "page_size": 5,
                    "total": len(agg_ua),
                    "total_pages": max(1, (len(agg_ua) + 4) // 5),
                },
            }
            set_cached("top_ua", top_ua)

            top_paths_all = _timed(
                "get_top_paths_all",
                lambda: db.analytics.get_top_paths(limit=100_000, min_count=min_count),
            )
            agg_paths = [{"path": p, "count": c} for p, c in top_paths_all]
            set_cached("agg:top_paths", agg_paths)
            top_paths = {
                "paths": agg_paths[:5],
                "pagination": {
                    "page": 1,
                    "page_size": 5,
                    "total": len(agg_paths),
                    "total_pages": max(1, (len(agg_paths) + 4) // 5),
                },
            }
            set_cached("top_paths", top_paths)

            attackers_all = _timed(
                "get_attackers_all",
                lambda: db.ip_stats.get_attackers_paginated(
                    page=1,
                    page_size=100_000,
                    sort_by="total_requests",
                    sort_order="desc",
                ),
            )
            set_cached("agg:attackers", attackers_all["attackers"])

            honeypot_all = _timed(
                "get_honeypot_all",
                lambda: db.access_logs.get_honeypot_paginated(
                    page=1, page_size=100_000, sort_by="count", sort_order="desc"
                ),
            )
            set_cached("agg:honeypot", honeypot_all["honeypots"])
        else:
            top_ua = _timed(
                "get_top_user_agents_paginated",
                lambda: db.analytics.get_top_user_agents_paginated(
                    page=1, page_size=5, min_count=min_count
                ),
            )
            top_paths = _timed(
                "get_top_paths_paginated",
                lambda: db.analytics.get_top_paths_paginated(
                    page=1, page_size=5, min_count=min_count
                ),
            )

        # --- Map data ---
        # Also used to derive top_ips (first 8), avoiding a redundant DB query
        if warmup_aggregation:
            map_ips_all = _timed(
                "get_all_ips_paginated_50k",
                lambda: db.ip_stats.get_all_ips_paginated(
                    page=1,
                    page_size=50_000,
                    sort_by="total_requests",
                    sort_order="desc",
                ),
            )
            set_cached("agg:map_ips", map_ips_all["ips"])
            total_ips = map_ips_all["pagination"]["total"]
            map_ips = {
                "ips": map_ips_all["ips"][:1000],
                "pagination": {
                    "page": 1,
                    "page_size": 1000,
                    "total": total_ips,
                    "total_pages": max(1, (total_ips + 999) // 1000),
                },
            }
        else:
            map_ips = _timed(
                "get_all_ips_paginated",
                lambda: db.ip_stats.get_all_ips_paginated(
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

        # --- Attack panel data (multi-page, default sort) ---
        attack_trends = _timed(
            "get_attack_types_daily",
            lambda: db.analytics.get_attack_types_daily(
                limit=10, days=7, offset_days=0
            ),
        )

        # Each panel below warms warmup_pages cache pages with ONE query each
        # (bulk fetch + in-Python slicing) rather than one query per page.
        _warm_pages(
            "attacks_all",
            lambda: db.analytics.get_attack_types_paginated(
                page=1,
                page_size=15 * warmup_pages,
                sort_by="timestamp",
                sort_order="desc",
            ),
            rows_key="attacks",
            total_key="total",
            page_size=15,
            key_fmt="attacks:{p}:timestamp:desc::",
        )

        _warm_pages(
            "attackers_all",
            lambda: db.ip_stats.get_attackers_paginated(
                page=1,
                page_size=10 * warmup_pages,
                sort_by="total_requests",
                sort_order="desc",
            ),
            rows_key="attackers",
            total_key="total_attackers",
            page_size=10,
            key_fmt="attackers:{p}:total_requests:desc",
        )

        credentials_bulk = _warm_pages(
            "credentials_all",
            lambda: db.credentials.get_paginated(
                page=1,
                page_size=5 * warmup_pages,
                sort_by="timestamp",
                sort_order="desc",
            ),
            rows_key="credentials",
            total_key="total",
            page_size=5,
            key_fmt="credentials:{p}:timestamp:desc",
        )

        _warm_pages(
            "honeypot_all",
            lambda: db.access_logs.get_honeypot_paginated(
                page=1, page_size=5 * warmup_pages, sort_by="count", sort_order="desc"
            ),
            rows_key="honeypots",
            total_key="total",
            page_size=5,
            key_fmt="honeypot:{p}:count:desc",
            clamp_pages=True,
        )

        # Derive credential count from the bulk credentials result
        stats["credential_count"] = credentials_bulk.get("pagination", {}).get(
            "total", 0
        )

        # Store everything in the cache (overwrites previous values)
        set_cached("stats", stats)
        set_cached("suspicious", suspicious)
        set_cached("top_ips", top_ips)
        if not warmup_aggregation:
            set_cached("top_ua", top_ua)
            set_cached("top_paths", top_paths)
        set_cached("map_ips", map_ips)

        # Attack trends cache (used by API endpoint)
        set_cached_table("api:attack_daily:10:7:0", attack_trends)

        app_logger.info(f"[Background Task] {task_name} cache refreshed successfully.")

    except Exception as e:
        app_logger.error(f"[Background Task] {task_name} failed: {e}")
