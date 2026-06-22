#!/usr/bin/env python3

"""
Dashboard page route.
Renders the main dashboard page with server-side data for initial load.
"""

import os
from pathlib import Path

import yaml
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from config import get_config
from dashboard_cache import get_cached, is_warm
from dependencies import get_db, get_templates
from logger import get_app_logger

router = APIRouter()


def _get_krawl_version() -> str:
    """Read version from Chart.yaml, with KRAWL_VERSION env var as override."""
    env = os.getenv("KRAWL_VERSION")
    if env:
        return env
    chart_path = Path(__file__).resolve().parent.parent.parent / "Chart.yaml"
    if chart_path.exists():
        with open(chart_path) as f:
            chart = yaml.safe_load(f)
        return str(chart.get("appVersion", "dev"))
    return "dev"


KRAWL_VERSION = _get_krawl_version()


@router.get("/healthz", include_in_schema=False)
async def healthz():
    """Liveness/readiness/startup probe target.

    Lives under the secret dashboard prefix, so it inherits that prefix's
    exemption from the ban-check and deception middleware — probes are never
    tracked, counted toward bans, or served a 429.
    """
    return JSONResponse({"status": "ok"})


@router.get("/metrics", include_in_schema=False)
async def metrics_endpoint(request: Request):
    if not get_config().metrics_enabled:
        raise HTTPException(status_code=404)
    # generate_latest() invokes KrawlMetricsCollector.collect(), which does
    # blocking cache/DB reads — run it off the event loop.
    import asyncio

    content = await asyncio.to_thread(generate_latest)
    return Response(content=content, media_type=CONTENT_TYPE_LATEST)


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
        stats = await asyncio.to_thread(db.access_logs.get_dashboard_counts)
        suspicious = await asyncio.to_thread(db.access_logs.get_recent_suspicious, 10)
        cred_result = await asyncio.to_thread(
            db.credentials.get_paginated, page=1, page_size=1
        )
        stats["credential_count"] = cred_result["pagination"]["total"]

    templates = get_templates()

    # Ensure stats is a clean dict with only serializable values
    clean_stats = {
        k: v
        for k, v in stats.items()
        if isinstance(v, (int, str, float, type(None), bool))
    }

    return templates.TemplateResponse(
        request,
        "dashboard/index.html",
        {
            "dashboard_path": dashboard_path,
            "stats": clean_stats,
            "suspicious_activities": suspicious,
            "krawl_version": KRAWL_VERSION,
        },
    )


@router.get("/ip/{ip_address:path}")
async def ip_page(ip_address: str, request: Request):
    import asyncio

    db = get_db()
    try:
        stats = await asyncio.to_thread(db.ip_stats.get_ip_stats_by_ip, ip_address)
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
                request,
                "dashboard/ip.html",
                {
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
