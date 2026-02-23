#!/usr/bin/env python3

"""
Dashboard JSON API routes.
Migrated from handler.py dashboard API endpoints.
All endpoints are prefixed with the secret dashboard path.
"""

import os
import json

from fastapi import APIRouter, Request, Response, Query
from fastapi.responses import JSONResponse, PlainTextResponse

from dependencies import get_db
from logger import get_app_logger

router = APIRouter()


def _no_cache_headers() -> dict:
    return {
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
        "Access-Control-Allow-Origin": "*",
    }


@router.get("/api/all-ip-stats")
async def all_ip_stats(request: Request):
    db = get_db()
    try:
        ip_stats_list = db.get_ip_stats(limit=500)
        return JSONResponse(
            content={"ips": ip_stats_list},
            headers=_no_cache_headers(),
        )
    except Exception as e:
        get_app_logger().error(f"Error fetching all IP stats: {e}")
        return JSONResponse(content={"error": str(e)}, headers=_no_cache_headers())


@router.get("/api/attackers")
async def attackers(
    request: Request,
    page: int = Query(1),
    page_size: int = Query(25),
    sort_by: str = Query("total_requests"),
    sort_order: str = Query("desc"),
):
    db = get_db()
    page = max(1, page)
    page_size = min(max(1, page_size), 100)

    try:
        result = db.get_attackers_paginated(
            page=page, page_size=page_size, sort_by=sort_by, sort_order=sort_order
        )
        return JSONResponse(content=result, headers=_no_cache_headers())
    except Exception as e:
        get_app_logger().error(f"Error fetching attackers: {e}")
        return JSONResponse(content={"error": str(e)}, headers=_no_cache_headers())


@router.get("/api/all-ips")
async def all_ips(
    request: Request,
    page: int = Query(1),
    page_size: int = Query(25),
    sort_by: str = Query("total_requests"),
    sort_order: str = Query("desc"),
):
    db = get_db()
    page = max(1, page)
    page_size = min(max(1, page_size), 10000)

    try:
        result = db.get_all_ips_paginated(
            page=page, page_size=page_size, sort_by=sort_by, sort_order=sort_order
        )
        return JSONResponse(content=result, headers=_no_cache_headers())
    except Exception as e:
        get_app_logger().error(f"Error fetching all IPs: {e}")
        return JSONResponse(content={"error": str(e)}, headers=_no_cache_headers())


@router.get("/api/ip-stats/{ip_address:path}")
async def ip_stats(ip_address: str, request: Request):
    db = get_db()
    try:
        stats = db.get_ip_stats_by_ip(ip_address)
        if stats:
            return JSONResponse(content=stats, headers=_no_cache_headers())
        else:
            return JSONResponse(
                content={"error": "IP not found"}, headers=_no_cache_headers()
            )
    except Exception as e:
        get_app_logger().error(f"Error fetching IP stats: {e}")
        return JSONResponse(content={"error": str(e)}, headers=_no_cache_headers())


@router.get("/api/honeypot")
async def honeypot(
    request: Request,
    page: int = Query(1),
    page_size: int = Query(5),
    sort_by: str = Query("count"),
    sort_order: str = Query("desc"),
):
    db = get_db()
    page = max(1, page)
    page_size = min(max(1, page_size), 100)

    try:
        result = db.get_honeypot_paginated(
            page=page, page_size=page_size, sort_by=sort_by, sort_order=sort_order
        )
        return JSONResponse(content=result, headers=_no_cache_headers())
    except Exception as e:
        get_app_logger().error(f"Error fetching honeypot data: {e}")
        return JSONResponse(content={"error": str(e)}, headers=_no_cache_headers())


@router.get("/api/credentials")
async def credentials(
    request: Request,
    page: int = Query(1),
    page_size: int = Query(5),
    sort_by: str = Query("timestamp"),
    sort_order: str = Query("desc"),
):
    db = get_db()
    page = max(1, page)
    page_size = min(max(1, page_size), 100)

    try:
        result = db.get_credentials_paginated(
            page=page, page_size=page_size, sort_by=sort_by, sort_order=sort_order
        )
        return JSONResponse(content=result, headers=_no_cache_headers())
    except Exception as e:
        get_app_logger().error(f"Error fetching credentials: {e}")
        return JSONResponse(content={"error": str(e)}, headers=_no_cache_headers())


@router.get("/api/top-ips")
async def top_ips(
    request: Request,
    page: int = Query(1),
    page_size: int = Query(5),
    sort_by: str = Query("count"),
    sort_order: str = Query("desc"),
):
    db = get_db()
    page = max(1, page)
    page_size = min(max(1, page_size), 100)

    try:
        result = db.get_top_ips_paginated(
            page=page, page_size=page_size, sort_by=sort_by, sort_order=sort_order
        )
        return JSONResponse(content=result, headers=_no_cache_headers())
    except Exception as e:
        get_app_logger().error(f"Error fetching top IPs: {e}")
        return JSONResponse(content={"error": str(e)}, headers=_no_cache_headers())


@router.get("/api/top-paths")
async def top_paths(
    request: Request,
    page: int = Query(1),
    page_size: int = Query(5),
    sort_by: str = Query("count"),
    sort_order: str = Query("desc"),
):
    db = get_db()
    page = max(1, page)
    page_size = min(max(1, page_size), 100)

    try:
        result = db.get_top_paths_paginated(
            page=page, page_size=page_size, sort_by=sort_by, sort_order=sort_order
        )
        return JSONResponse(content=result, headers=_no_cache_headers())
    except Exception as e:
        get_app_logger().error(f"Error fetching top paths: {e}")
        return JSONResponse(content={"error": str(e)}, headers=_no_cache_headers())


@router.get("/api/top-user-agents")
async def top_user_agents(
    request: Request,
    page: int = Query(1),
    page_size: int = Query(5),
    sort_by: str = Query("count"),
    sort_order: str = Query("desc"),
):
    db = get_db()
    page = max(1, page)
    page_size = min(max(1, page_size), 100)

    try:
        result = db.get_top_user_agents_paginated(
            page=page, page_size=page_size, sort_by=sort_by, sort_order=sort_order
        )
        return JSONResponse(content=result, headers=_no_cache_headers())
    except Exception as e:
        get_app_logger().error(f"Error fetching top user agents: {e}")
        return JSONResponse(content={"error": str(e)}, headers=_no_cache_headers())


@router.get("/api/attack-types-stats")
async def attack_types_stats(
    request: Request,
    limit: int = Query(20),
):
    db = get_db()
    limit = min(max(1, limit), 100)

    try:
        result = db.get_attack_types_stats(limit=limit)
        return JSONResponse(content=result, headers=_no_cache_headers())
    except Exception as e:
        get_app_logger().error(f"Error fetching attack types stats: {e}")
        return JSONResponse(content={"error": str(e)}, headers=_no_cache_headers())


@router.get("/api/attack-types")
async def attack_types(
    request: Request,
    page: int = Query(1),
    page_size: int = Query(5),
    sort_by: str = Query("timestamp"),
    sort_order: str = Query("desc"),
):
    db = get_db()
    page = max(1, page)
    page_size = min(max(1, page_size), 100)

    try:
        result = db.get_attack_types_paginated(
            page=page, page_size=page_size, sort_by=sort_by, sort_order=sort_order
        )
        return JSONResponse(content=result, headers=_no_cache_headers())
    except Exception as e:
        get_app_logger().error(f"Error fetching attack types: {e}")
        return JSONResponse(content={"error": str(e)}, headers=_no_cache_headers())


@router.get("/api/raw-request/{log_id:int}")
async def raw_request(log_id: int, request: Request):
    db = get_db()
    try:
        raw = db.get_raw_request_by_id(log_id)
        if raw is None:
            return JSONResponse(
                content={"error": "Raw request not found"}, status_code=404
            )
        return JSONResponse(content={"raw_request": raw}, headers=_no_cache_headers())
    except Exception as e:
        get_app_logger().error(f"Error fetching raw request: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.get("/api/get_banlist")
async def get_banlist(request: Request, fwtype: str = Query("iptables")):
    config = request.app.state.config

    filename = f"{fwtype}_banlist.txt"
    if fwtype == "raw":
        filename = "malicious_ips.txt"

    file_path = os.path.join(config.exports_path, filename)

    try:
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                content = f.read()
            return Response(
                content=content,
                status_code=200,
                media_type="text/plain",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Content-Length": str(len(content)),
                },
            )
        else:
            return PlainTextResponse("File not found", status_code=404)
    except Exception as e:
        get_app_logger().error(f"Error serving malicious IPs file: {e}")
        return PlainTextResponse("Internal server error", status_code=500)


@router.get("/api/download/malicious_ips.txt")
async def download_malicious_ips(request: Request):
    config = request.app.state.config
    file_path = os.path.join(config.exports_path, "malicious_ips.txt")

    try:
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                content = f.read()
            return Response(
                content=content,
                status_code=200,
                media_type="text/plain",
                headers={
                    "Content-Disposition": 'attachment; filename="malicious_ips.txt"',
                    "Content-Length": str(len(content)),
                },
            )
        else:
            return PlainTextResponse("File not found", status_code=404)
    except Exception as e:
        get_app_logger().error(f"Error serving malicious IPs file: {e}")
        return PlainTextResponse("Internal server error", status_code=500)
