#!/usr/bin/env python3

"""
Dashboard page route.
Renders the main dashboard page with server-side data for initial load.
"""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from logger import get_app_logger

from dependencies import get_db, get_templates

router = APIRouter()


@router.get("")
@router.get("/")
async def dashboard_page(request: Request):
    db = get_db()
    config = request.app.state.config
    dashboard_path = "/" + config.dashboard_secret_path.lstrip("/")

    # Get initial data for server-rendered sections
    stats = db.get_dashboard_counts()
    suspicious = db.get_recent_suspicious(limit=10)

    # Get credential count for the stats card
    cred_result = db.get_credentials_paginated(page=1, page_size=1)
    stats["credential_count"] = cred_result["pagination"]["total"]

    templates = get_templates()
    return templates.TemplateResponse(
        "dashboard/index.html",
        {
            "request": request,
            "dashboard_path": dashboard_path,
            "stats": stats,
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

            templates = get_templates()
            return templates.TemplateResponse(
                "dashboard/ip.html",
                {
                    "request": request,
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
