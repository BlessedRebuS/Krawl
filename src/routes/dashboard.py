#!/usr/bin/env python3

"""
Dashboard page route.
Renders the main dashboard page with server-side data for initial load.
"""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from logger import get_app_logger

from dependencies import get_db, get_templates
from config import get_config
from dashboard_cache import get_cached, is_warm

router = APIRouter()


@router.get("")
@router.get("/")
async def dashboard_page(request: Request):
    config = request.app.state.config
    dashboard_path = "/" + config.dashboard_secret_path.lstrip("/")

    # Serve from pre-computed cache when available, fall back to live queries
    if get_config().dashboard_cache_warmup and is_warm():
        stats = get_cached("stats")
        suspicious = get_cached("suspicious")
    else:
        import asyncio

        db = get_db()
        stats = await asyncio.to_thread(db.get_dashboard_counts)
        suspicious = await asyncio.to_thread(db.get_recent_suspicious, 10)
        cred_result = await asyncio.to_thread(
            db.get_credentials_paginated, page=1, page_size=1
        )
        stats["credential_count"] = cred_result["pagination"]["total"]

    templates = get_templates()
    return templates.TemplateResponse(
        request,
        "dashboard/index.html",
        {
            "dashboard_path": dashboard_path,
            "stats": stats,
            "suspicious_activities": suspicious,
        },
    )


@router.get("/ip/{ip_address:path}")
async def ip_page(ip_address: str, request: Request):
    import asyncio

    db = get_db()
    try:
        stats = await asyncio.to_thread(db.get_ip_stats_by_ip, ip_address)
        config = request.app.state.config
        dashboard_path = "/" + config.dashboard_secret_path.lstrip("/")

        if stats:
            # Transform fields for template compatibility
            list_on = stats.get("list_on") or {}
            stats["blocklist_memberships"] = list(list_on.keys()) if list_on else []
            stats["reverse_dns"] = stats.get("reverse")

            templates = get_templates()
            return templates.TemplateResponse(
                request,
                "dashboard/ip.html",
                {
                    "dashboard_path": dashboard_path,
                    "stats": stats,
                    "ip_address": ip_address,
                },
            )
        else:
            return JSONResponse(
                content={"error": "IP not found"},
            )
    except Exception as e:
        get_app_logger().error(f"Error fetching IP stats: {e}")
        return JSONResponse(content={"error": str(e)})
