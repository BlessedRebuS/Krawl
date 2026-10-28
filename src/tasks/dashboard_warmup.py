# tasks/dashboard_warmup.py

"""
Pre-computes all Overview tab data and stores it in the cache.
Lets the dashboard respond instantly without hitting the database.
"""

import time

import metrics
from config import get_config
from dashboard_cache import (
    get_cached,
    get_cached_table,
    set_cached,
    set_cached_list,
    set_cached_table,
)
from database import get_database
from logger import get_app_logger
from routes.api import build_campaign_stats
from routes.htmx import CAMPAIGN_TABLE_LIMIT

app_logger = get_app_logger()

# Warmed table pages must outlive the 5-minute schedule: with the default
# 2-minute table TTL they went cold for 3 minutes of every 5, and the next
# visitor paid the full query.
WARM_TTL = 600
# Whole-log rankings barely move: refreshed every 6th run (30 min) or when
# missing, so they must outlive that gap.
SLOW_TTL = 2400


# ----------------------
# TASK CONFIG
# ----------------------
TASK_CONFIG = {
    "name": "dashboard-warmup",
    "cron": "*/5 * * * *",
    "enabled": True,
    "run_when_loaded": True,
    # Warms the shared Redis cache; N pods writing it is N times the work.
    "single_pod": True,
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
                    ttl=WARM_TTL,
                    value={
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

        slow_run = int(time.time() // 300) % 6 == 0

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
            if slow_run or get_cached("top_ua") is None:
                top_ua_all = _timed(
                    "get_top_ua_all",
                    lambda: db.analytics.get_top_user_agents(
                        limit=100_000, min_count=min_count
                    ),
                )
                agg_ua = [{"user_agent": ua, "count": c} for ua, c in top_ua_all]
                set_cached_list("agg:top_ua", agg_ua, ttl=SLOW_TTL)
                top_ua = {
                    "user_agents": agg_ua[:5],
                    "pagination": {
                        "page": 1,
                        "page_size": 5,
                        "total": len(agg_ua),
                        "total_pages": max(1, (len(agg_ua) + 4) // 5),
                    },
                }
                set_cached("top_ua", top_ua, ttl=SLOW_TTL)
                del top_ua_all, agg_ua

            if slow_run or get_cached("top_paths") is None:
                top_paths_all = _timed(
                    "get_top_paths_all",
                    lambda: db.analytics.get_top_paths(
                        limit=100_000, min_count=min_count
                    ),
                )
                agg_paths = [{"path": p, "count": c} for p, c in top_paths_all]
                set_cached_list("agg:top_paths", agg_paths, ttl=SLOW_TTL)
                top_paths = {
                    "paths": agg_paths[:5],
                    "pagination": {
                        "page": 1,
                        "page_size": 5,
                        "total": len(agg_paths),
                        "total_pages": max(1, (len(agg_paths) + 4) // 5),
                    },
                }
                set_cached("top_paths", top_paths, ttl=SLOW_TTL)
                del top_paths_all, agg_paths

            attackers_all = _timed(
                "get_attackers_all",
                lambda: db.ip_stats.get_attackers_paginated(
                    page=1,
                    page_size=100_000,
                    sort_by="total_requests",
                    sort_order="desc",
                ),
            )
            set_cached_list("agg:attackers", attackers_all["attackers"])
            del attackers_all

            honeypot_all = _timed(
                "get_honeypot_all",
                lambda: db.access_logs.get_honeypot_paginated(
                    page=1, page_size=100_000, sort_by="count", sort_order="desc"
                ),
            )
            set_cached_list("agg:honeypot", honeypot_all["honeypots"])
            del honeypot_all
        else:
            if slow_run or get_cached("top_ua") is None:
                top_ua = _timed(
                    "get_top_user_agents_paginated",
                    lambda: db.analytics.get_top_user_agents_paginated(
                        page=1, page_size=5, min_count=min_count
                    ),
                )
                set_cached("top_ua", top_ua, ttl=SLOW_TTL)
            if slow_run or get_cached("top_paths") is None:
                top_paths = _timed(
                    "get_top_paths_paginated",
                    lambda: db.analytics.get_top_paths_paginated(
                        page=1, page_size=5, min_count=min_count
                    ),
                )
                set_cached("top_paths", top_paths, ttl=SLOW_TTL)

        # --- Top IPs (the map's default Recent sort is fast live, not warmed) ---
        top_by_requests = _timed(
            "get_top_ips",
            lambda: db.ip_stats.get_all_ips_paginated(
                page=1, page_size=8, sort_by="total_requests", sort_order="desc"
            ),
        )
        total_ips = top_by_requests["pagination"]["total"]
        top_ips = {
            "ips": [
                {
                    "ip": ip["ip"],
                    "count": ip["total_requests"],
                    "category": ip.get("category") or "unknown",
                }
                for ip in top_by_requests["ips"]
            ],
            "pagination": {
                "page": 1,
                "page_size": 8,
                "total": total_ips,
                "total_pages": max(1, (total_ips + 7) // 8),
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
            key_fmt="attacks:{p}:timestamp:desc:::::",
        )

        # With aggregation on, the routes page the agg:* lists instead.
        if not warmup_aggregation:
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
            key_fmt="credentials:{p}:timestamp:desc:",
        )

        if not warmup_aggregation:
            _warm_pages(
                "honeypot_all",
                lambda: db.access_logs.get_honeypot_paginated(
                    page=1,
                    page_size=5 * warmup_pages,
                    sort_by="count",
                    sort_order="desc",
                ),
                rows_key="honeypots",
                total_key="total",
                page_size=5,
                key_fmt="honeypot:{p}:count:desc",
                clamp_pages=True,
            )

        # --- Threats tab ---
        # The tab opens on an all-time cluster scan and the 1-day campaign
        # chart, which are the two slowest reads in the dashboard. Warm the
        # exact keys the tab requests on open; other spans stay on demand.
        clusters = _timed(
            "campaign_clusters_all",
            lambda: db.payloads.get_campaign_clusters(limit=CAMPAIGN_TABLE_LIMIT),
        )
        set_cached_table("clusters:all", {"clusters": clusters}, ttl=WARM_TTL)

        top_campaigns = _timed(
            "campaign_stats_top",
            lambda: build_campaign_stats(db, 8, days=1, offset=0),
        )
        set_cached_table("api:campaign_stats:8:1:0", top_campaigns, ttl=WARM_TTL)

        _warm_pages(
            "global_filenames_all",
            lambda: db.payloads.get_global_index(page=1, page_size=10 * warmup_pages),
            rows_key="index",
            total_key="total",
            page_size=10,
            key_fmt="filenames:{p}",
        )

        # First pages of the panels whose totals scan the whole access log,
        # under the exact keys their routes read (dashboard defaults).
        key = "suspicious:1:25:desc:"
        set_cached_table(
            key,
            _timed(
                key,
                lambda: db.access_logs.get_recent_suspicious_paginated(
                    page=1, page_size=25
                ),
            ),
            ttl=WARM_TTL,
        )

        # Targeted Domains: whole-log GROUP BY host, on the slow schedule.
        key = "targeted-domains:1::count:desc"
        if slow_run or get_cached_table(key) is None:
            domains = _timed(
                key, lambda: db.access_logs.get_targeted_domains(page=1, page_size=10)
            )
            set_cached_table(key, domains, ttl=SLOW_TTL)

        # Last-24-hours panel: the expanded view's 100 rows; the collapsed
        # panel slices the first few from the same entry.
        attention = _timed(
            "get_attention_summary",
            lambda: db.ip_stats.get_attention_summary(limit=100),
        )

        # Derive credential count from the bulk credentials result
        stats["credential_count"] = credentials_bulk.get("pagination", {}).get(
            "total", 0
        )

        # Store everything in the cache (overwrites previous values)
        set_cached("stats", stats)
        set_cached("suspicious", suspicious)
        set_cached("top_ips", top_ips)
        set_cached("attention", attention)

        # Attack trends cache (used by API endpoint)
        set_cached_table("api:attack_daily:10:7:0", attack_trends, ttl=WARM_TTL)

        app_logger.info(f"[Background Task] {task_name} cache refreshed successfully.")

    except Exception as e:
        app_logger.error(f"[Background Task] {task_name} failed: {e}")
