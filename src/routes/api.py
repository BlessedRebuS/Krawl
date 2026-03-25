#!/usr/bin/env python3

"""
Dashboard JSON API routes.
Migrated from handler.py dashboard API endpoints.
All endpoints are prefixed with the secret dashboard path.
"""

import asyncio
import hashlib
import hmac
import os
import secrets
import time

from fastapi import APIRouter, Request, Response, Query, Cookie
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

from dependencies import get_db, get_client_ip
from logger import get_app_logger
from config import get_config
from dashboard_cache import (
    get_cached,
    is_warm,
    invalidate_table_cache,
    get_cached_table,
    set_cached_table,
)

# Server-side session token store (valid tokens for authenticated sessions)
_auth_tokens: set = set()

# Bruteforce protection: tracks failed attempts per IP
# { ip: { "attempts": int, "locked_until": float } }
_auth_attempts: dict = {}
_AUTH_MAX_ATTEMPTS = 5
_AUTH_BASE_LOCKOUT = 30  # seconds, doubles on each lockout

router = APIRouter()


def _no_cache_headers() -> dict:
    return {
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
        "Access-Control-Allow-Origin": "*",
    }


class AuthRequest(BaseModel):
    fingerprint: str


def verify_auth(request: Request) -> bool:
    """Check if the request has a valid auth session cookie."""
    token = request.cookies.get("krawl_auth")
    return token is not None and token in _auth_tokens


@router.post("/api/auth")
async def authenticate(request: Request, body: AuthRequest):
    ip = get_client_ip(request)

    # Check if IP is currently locked out
    record = _auth_attempts.get(ip)
    if record and record["locked_until"] > time.time():
        remaining = int(record["locked_until"] - time.time())
        return JSONResponse(
            content={
                "authenticated": False,
                "error": f"Too many attempts. Try again in {remaining}s",
                "locked": True,
                "retry_after": remaining,
            },
            status_code=429,
        )

    config = request.app.state.config
    expected = hashlib.sha256(config.dashboard_password.encode()).hexdigest()
    if hmac.compare_digest(body.fingerprint, expected):
        # Success — clear failed attempts
        _auth_attempts.pop(ip, None)
        get_app_logger().info(f"[AUTH] Successful login from {ip}")
        token = secrets.token_hex(32)
        _auth_tokens.add(token)
        response = JSONResponse(content={"authenticated": True})
        response.set_cookie(
            key="krawl_auth",
            value=token,
            httponly=True,
            samesite="strict",
        )
        return response

    # Failed attempt — track and possibly lock out
    get_app_logger().warning(f"[AUTH] Failed login attempt from {ip}")
    if not record:
        record = {"attempts": 0, "locked_until": 0, "lockouts": 0}
        _auth_attempts[ip] = record
    record["attempts"] += 1

    if record["attempts"] >= _AUTH_MAX_ATTEMPTS:
        lockout = _AUTH_BASE_LOCKOUT * (2 ** record["lockouts"])
        record["locked_until"] = time.time() + lockout
        record["lockouts"] += 1
        record["attempts"] = 0
        get_app_logger().warning(
            f"Auth bruteforce: IP {ip} locked out for {lockout}s "
            f"(lockout #{record['lockouts']})"
        )
        return JSONResponse(
            content={
                "authenticated": False,
                "error": f"Too many attempts. Locked for {lockout}s",
                "locked": True,
                "retry_after": lockout,
            },
            status_code=429,
        )

    remaining_attempts = _AUTH_MAX_ATTEMPTS - record["attempts"]
    return JSONResponse(
        content={
            "authenticated": False,
            "error": f"Invalid password. {remaining_attempts} attempt{'s' if remaining_attempts != 1 else ''} remaining",
        },
        status_code=401,
    )


@router.post("/api/auth/logout")
async def logout(request: Request):
    token = request.cookies.get("krawl_auth")
    if token and token in _auth_tokens:
        _auth_tokens.discard(token)
    response = JSONResponse(content={"authenticated": False})
    response.delete_cookie(key="krawl_auth")
    return response


@router.get("/api/auth/check")
async def auth_check(request: Request):
    """Check if the current session is authenticated."""
    if verify_auth(request):
        return JSONResponse(content={"authenticated": True})
    return JSONResponse(content={"authenticated": False}, status_code=401)


# ── Protected Ban Management API ─────────────────────────────────────


class BanOverrideRequest(BaseModel):
    ip: str
    action: str  # "ban", "unban", or "reset"


@router.post("/api/ban-override")
async def ban_override(request: Request, body: BanOverrideRequest):
    if not verify_auth(request):
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)

    db = get_db()
    action_map = {"ban": True, "unban": False, "reset": None}
    if body.action not in action_map:
        return JSONResponse(
            content={"error": "Invalid action. Use: ban, unban, reset"},
            status_code=400,
        )

    if body.action == "ban":
        success = await asyncio.to_thread(db.force_ban_ip, body.ip)
    else:
        success = await asyncio.to_thread(
            db.set_ban_override, body.ip, action_map[body.action]
        )

    if success:
        get_app_logger().info(f"Ban override: {body.action} on IP {body.ip}")
        invalidate_table_cache()
        return JSONResponse(
            content={"success": True, "ip": body.ip, "action": body.action}
        )
    return JSONResponse(content={"error": "IP not found"}, status_code=404)


# ── Protected IP Tracking API ────────────────────────────────────────


class TrackIpRequest(BaseModel):
    ip: str
    action: str  # "track" or "untrack"


@router.post("/api/track-ip")
async def track_ip(request: Request, body: TrackIpRequest):
    if not verify_auth(request):
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)

    db = get_db()
    if body.action == "track":
        success = await asyncio.to_thread(db.track_ip, body.ip)
    elif body.action == "untrack":
        success = await asyncio.to_thread(db.untrack_ip, body.ip)
    else:
        return JSONResponse(
            content={"error": "Invalid action. Use: track, untrack"},
            status_code=400,
        )

    if success:
        get_app_logger().info(f"IP tracking: {body.action} on IP {body.ip}")
        invalidate_table_cache()
        return JSONResponse(
            content={"success": True, "ip": body.ip, "action": body.action}
        )
    return JSONResponse(content={"error": "IP not found"}, status_code=404)


@router.get("/api/all-ip-stats")
async def all_ip_stats(request: Request):
    cached = get_cached_table("api:all_ip_stats")
    if cached:
        return JSONResponse(content=cached, headers=_no_cache_headers())

    db = get_db()
    try:
        ip_stats_list = await asyncio.to_thread(db.get_ip_stats, limit=500)
        result = {"ips": ip_stats_list}
        set_cached_table("api:all_ip_stats", result)
        return JSONResponse(
            content=result,
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
        result = await asyncio.to_thread(
            db.get_attackers_paginated,
            page=page,
            page_size=page_size,
            sort_by=sort_by,
            sort_order=sort_order,
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
    page = max(1, page)
    page_size = min(max(1, page_size), 10000)

    # Serve from cache on default map request (top 100 IPs)
    if (
        get_config().dashboard_cache_warmup
        and page == 1
        and page_size == 100
        and sort_by == "total_requests"
        and sort_order == "desc"
        and is_warm()
    ):
        cached = get_cached("map_ips")
        if cached:
            return JSONResponse(content=cached, headers=_no_cache_headers())

    db = get_db()
    try:
        result = await asyncio.to_thread(
            db.get_all_ips_paginated,
            page=page,
            page_size=page_size,
            sort_by=sort_by,
            sort_order=sort_order,
        )
        return JSONResponse(content=result, headers=_no_cache_headers())
    except Exception as e:
        get_app_logger().error(f"Error fetching all IPs: {e}")
        return JSONResponse(content={"error": str(e)}, headers=_no_cache_headers())


@router.get("/api/ip-stats/{ip_address:path}")
async def ip_stats(ip_address: str, request: Request):
    db = get_db()
    try:
        stats = await asyncio.to_thread(db.get_ip_stats_by_ip, ip_address)
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
        result = await asyncio.to_thread(
            db.get_honeypot_paginated,
            page=page,
            page_size=page_size,
            sort_by=sort_by,
            sort_order=sort_order,
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
        result = await asyncio.to_thread(
            db.get_credentials_paginated,
            page=page,
            page_size=page_size,
            sort_by=sort_by,
            sort_order=sort_order,
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
        result = await asyncio.to_thread(
            db.get_top_ips_paginated,
            page=page,
            page_size=page_size,
            sort_by=sort_by,
            sort_order=sort_order,
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
        result = await asyncio.to_thread(
            db.get_top_paths_paginated,
            page=page,
            page_size=page_size,
            sort_by=sort_by,
            sort_order=sort_order,
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
        result = await asyncio.to_thread(
            db.get_top_user_agents_paginated,
            page=page,
            page_size=page_size,
            sort_by=sort_by,
            sort_order=sort_order,
        )
        return JSONResponse(content=result, headers=_no_cache_headers())
    except Exception as e:
        get_app_logger().error(f"Error fetching top user agents: {e}")
        return JSONResponse(content={"error": str(e)}, headers=_no_cache_headers())


@router.get("/api/attack-types-stats")
async def attack_types_stats(
    request: Request,
    limit: int = Query(20),
    ip_filter: str = Query(None),
):
    limit = min(max(1, limit), 100)

    cache_key = f"api:attack_stats:{limit}:{ip_filter or ''}"
    cached = get_cached_table(cache_key)
    if cached:
        return JSONResponse(content=cached, headers=_no_cache_headers())

    db = get_db()
    try:
        result = await asyncio.to_thread(
            db.get_attack_types_stats, limit=limit, ip_filter=ip_filter
        )
        set_cached_table(cache_key, result)
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
        result = await asyncio.to_thread(
            db.get_attack_types_paginated,
            page=page,
            page_size=page_size,
            sort_by=sort_by,
            sort_order=sort_order,
        )
        return JSONResponse(content=result, headers=_no_cache_headers())
    except Exception as e:
        get_app_logger().error(f"Error fetching attack types: {e}")
        return JSONResponse(content={"error": str(e)}, headers=_no_cache_headers())


@router.get("/api/raw-request/{log_id:int}")
async def raw_request(log_id: int, request: Request):
    db = get_db()
    try:
        raw = await asyncio.to_thread(db.get_raw_request_by_id, log_id)
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
