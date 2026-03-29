#!/usr/bin/env python3

"""
Dashboard page route.
Renders the main dashboard page with server-side data for initial load.
"""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from logger import get_app_logger

from dependencies import get_db, get_templates
from dashboard_cache import get_cached, is_warm

router = APIRouter()


@router.get("")
@router.get("/")
async def dashboard_page(request: Request):
    config = request.app.state.config
    dashboard_path = "/" + config.dashboard_secret_path.lstrip("/")

    # Serve from pre-computed cache when available, fall back to live queries
    if is_warm():
        stats = get_cached("stats")
        suspicious = get_cached("suspicious")
    else:
        db = get_db()
        stats = db.get_dashboard_counts()
        suspicious = db.get_recent_suspicious(limit=10)
        cred_result = db.get_credentials_paginated(page=1, page_size=1)
        stats["credential_count"] = cred_result["pagination"]["total"]

    templates = get_templates()
    
    # Ensure stats is a clean dict with only serializable values
    clean_stats = {k: v for k, v in stats.items() if isinstance(v, (int, str, float, type(None), bool))}
    
    return templates.TemplateResponse(
        request,
        "dashboard/index.html",
        {
            "dashboard_path": dashboard_path,
            "stats": clean_stats,
            "suspicious_activities": suspicious,
        },
    )


@router.get("/ip/{ip_address:path}")
async def ip_page(ip_address: str, request: Request):
    db = get_db()
    try:
        stats = db.get_ip_stats_by_ip(ip_address)
        config = request.app.state.config
        dashboard_path = "/" + config.dashboard_secret_path.lstrip("/")

        if stats:
            # Transform fields for template compatibility
            list_on = stats.get("list_on") or {}
            stats["blocklist_memberships"] = list(list_on.keys()) if list_on else []
            stats["reverse_dns"] = stats.get("reverse")

            # Filter out unhashable types (dicts, lists) for Jinja2 template engine compatibility
            clean_stats = {}
            for k, v in stats.items():
                if isinstance(v, (int, str, float, type(None), bool)):
                    clean_stats[k] = v
                elif k == "blocklist_memberships" and isinstance(v, list):
                    # Keep list of strings (blocklist names)
                    clean_stats[k] = v

            templates = get_templates()
            return templates.TemplateResponse(
                "dashboard/ip.html",
                {
                    "request": request,
                    "dashboard_path": dashboard_path,
                    "stats": clean_stats,
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
