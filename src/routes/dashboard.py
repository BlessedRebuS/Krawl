#!/usr/bin/env python3

"""
Dashboard page route.
Renders the main dashboard page with server-side data for initial load.
"""

from fastapi import APIRouter, Request

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
    suspicious = db.get_recent_suspicious(limit=20)

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
