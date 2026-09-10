#!/usr/bin/env python3

"""
Dashboard JSON API routes.
Migrated from handler.py dashboard API endpoints.
All endpoints are prefixed with the secret dashboard path.
"""

import asyncio
import base64
import email
import hmac
import io
import re
import secrets
import time
import zipfile
from datetime import UTC, datetime, timedelta
from email import policy

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyCookie
from pydantic import BaseModel, validator

from auth_store import (
    clear_attempts,
    create_session,
    destroy_session,
    get_attempts,
    is_valid_session,
    save_attempts,
)
from config import get_config
from dashboard_cache import (
    get_cached,
    get_cached_list_page,
    get_cached_table,
    invalidate_table_cache,
    is_warm,
    set_cached_table,
)
from dependencies import get_client_ip, get_db
from logger import get_app_logger

# Sessions and bruteforce counters live in auth_store: Redis in scalable mode
# so they are shared by every replica, a local dict in standalone.
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


def _parse_day(day: str):
    """ISO date string -> datetime.date, or None when absent/invalid."""
    if not day:
        return None
    try:
        return datetime.fromisoformat(day.strip()).date()
    except ValueError:
        return None


def _campaign_window(day: str = "", days: int = 0, offset: int = 0):
    """Range window for the campaigns filter.

    ``day``: explicit ISO date -> that single day.
    ``days``: span length (1/7/30); window is the ``days`` days ending
    ``offset*days`` days ago (mirrors the attack-trends period pager).
    Returns (start_dt, end_dt) naive datetimes, or None for the global view.
    """
    from datetime import time

    if day:
        d = _parse_day(day)
        if d is None:
            return None
        start = datetime.combine(d, time.min)
        return start, start + timedelta(days=1)

    if days:
        days = min(max(1, days), 90)
        offset = max(0, offset)
        end_date = (datetime.now() - timedelta(days=offset * days)).date()
        start_date = end_date - timedelta(days=days - 1)
        start = datetime.combine(start_date, time.min)
        end = datetime.combine(end_date, time.min) + timedelta(days=1)
        return start, end

    return None


class AuthRequest(BaseModel):
    password: str


def verify_auth(request: Request) -> bool:
    """Check if the request has a valid auth session cookie."""
    return is_valid_session(request.cookies.get("krawl_auth"))


class Unauthorized(Exception):
    """Raised by require_auth; rendered as 401 JSON by the app handler."""


# Declared as a security scheme so FastAPI documents the session cookie itself
# (lock icons in /docs) instead of us post-processing the OpenAPI schema.
_cookie_scheme = APIKeyCookie(
    name="krawl_auth",
    auto_error=False,
    description="Session cookie obtained via POST /api/auth",
)


def require_auth(token: str | None = Depends(_cookie_scheme)) -> None:
    """Route dependency: 401 JSON unless the session cookie is valid."""
    if not is_valid_session(token):
        raise Unauthorized()


@router.post("/api/auth")
async def authenticate(request: Request, body: AuthRequest):
    ip = get_client_ip(request)

    # Check if IP is currently locked out
    record = get_attempts(ip)
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
    expected = config.dashboard_password.strip()
    if hmac.compare_digest(body.password, expected):
        # Success — clear failed attempts
        clear_attempts(ip)
        get_app_logger().info(f"[AUTH] Successful login from {ip}")
        token = secrets.token_hex(32)
        create_session(token)
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
    record["attempts"] += 1

    if record["attempts"] >= _AUTH_MAX_ATTEMPTS:
        lockout = _AUTH_BASE_LOCKOUT * (2 ** record["lockouts"])
        record["locked_until"] = time.time() + lockout
        record["lockouts"] += 1
        record["attempts"] = 0
        save_attempts(ip, record)
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

    save_attempts(ip, record)
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
    destroy_session(request.cookies.get("krawl_auth"))
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


@router.post("/api/ban-override", dependencies=[Depends(require_auth)])
async def ban_override(request: Request, body: BanOverrideRequest):
    db = get_db()
    action_map = {"ban": True, "unban": False, "reset": None}
    if body.action not in action_map:
        return JSONResponse(
            content={"error": "Invalid action. Use: ban, unban, reset"},
            status_code=400,
        )

    if body.action == "ban":
        success = await asyncio.to_thread(db.ip_stats.force_ban, body.ip)
    else:
        success = await asyncio.to_thread(
            db.ip_stats.set_ban_override, body.ip, action_map[body.action]
        )

    if success:
        get_app_logger().info(f"Ban override: {body.action} on IP {body.ip}")
        invalidate_table_cache()
        return JSONResponse(
            content={"success": True, "ip": body.ip, "action": body.action}
        )
    return JSONResponse(content={"error": "IP not found"}, status_code=404)


class TimeoutExemptRequest(BaseModel):
    ip: str
    action: str  # "exempt" or "reset"


@router.post("/api/timeout-exempt", dependencies=[Depends(require_auth)])
async def timeout_exempt(request: Request, body: TimeoutExemptRequest):
    action_map = {"exempt": True, "reset": False}
    if body.action not in action_map:
        return JSONResponse(
            content={"error": "Invalid action. Use: exempt, reset"},
            status_code=400,
        )

    db = get_db()
    success = await asyncio.to_thread(
        db.ip_stats.set_timeout_exempt, body.ip, action_map[body.action]
    )
    if success:
        get_app_logger().info(f"Timeout exempt: {body.action} on IP {body.ip}")
        invalidate_table_cache()
        return JSONResponse(
            content={"success": True, "ip": body.ip, "action": body.action}
        )
    return JSONResponse(content={"error": "IP not found"}, status_code=404)


# ── Protected IP Tracking API ────────────────────────────────────────


class TrackIpRequest(BaseModel):
    ip: str
    action: str  # "track" or "untrack"


@router.post("/api/track-ip", dependencies=[Depends(require_auth)])
async def track_ip(request: Request, body: TrackIpRequest):
    db = get_db()
    if body.action == "track":
        success = await asyncio.to_thread(db.ip_stats.track_ip, body.ip)
    elif body.action == "untrack":
        success = await asyncio.to_thread(db.ip_stats.untrack_ip, body.ip)
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
        ip_stats_list = await asyncio.to_thread(db.ip_stats.get_ip_stats, limit=500)
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
            db.ip_stats.get_attackers_paginated,
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
    config = get_config()

    # Serve from full aggregation cache (up to 50k IPs, default sort only)
    if (
        config.dashboard_cache_warmup
        and config.dashboard_warmup_aggregation
        and sort_by == "total_requests"
        and sort_order == "desc"
        and is_warm()
    ):
        sliced = get_cached_list_page("agg:map_ips", page=page, page_size=page_size)
        if sliced is not None:
            return JSONResponse(
                content={"ips": sliced["items"], "pagination": sliced["pagination"]},
                headers=_no_cache_headers(),
            )

    # Serve from warmup cache on default map request (top 1000 IPs)
    if (
        config.dashboard_cache_warmup
        and page == 1
        and page_size == 1000
        and sort_by == "total_requests"
        and sort_order == "desc"
        and is_warm()
    ):
        cached = get_cached("map_ips")
        if cached:
            return JSONResponse(content=cached, headers=_no_cache_headers())

    # Check table cache for any paginated request
    cache_key = f"all_ips:{page}:{page_size}:{sort_by}:{sort_order}"
    cached = get_cached_table(cache_key)
    if cached:
        return JSONResponse(content=cached, headers=_no_cache_headers())

    db = get_db()
    try:
        result = await asyncio.to_thread(
            db.ip_stats.get_all_ips_paginated,
            page=page,
            page_size=page_size,
            sort_by=sort_by,
            sort_order=sort_order,
        )
        set_cached_table(cache_key, result)
        return JSONResponse(content=result, headers=_no_cache_headers())
    except Exception as e:
        get_app_logger().error(f"Error fetching all IPs: {e}")
        return JSONResponse(content={"error": str(e)}, headers=_no_cache_headers())


@router.get("/api/ip-stats/{ip_address:path}")
async def ip_stats(ip_address: str, request: Request):
    db = get_db()
    try:
        stats = await asyncio.to_thread(db.ip_stats.get_ip_stats_by_ip, ip_address)
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
            db.access_logs.get_honeypot_paginated,
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
            db.credentials.get_paginated,
            page=page,
            page_size=page_size,
            sort_by=sort_by,
            sort_order=sort_order,
        )
        return JSONResponse(content=result, headers=_no_cache_headers())
    except Exception as e:
        get_app_logger().error(f"Error fetching credentials: {e}")
        return JSONResponse(content={"error": str(e)}, headers=_no_cache_headers())


@router.get("/api/download-credentials")
async def download_credentials(request: Request):
    """Download unique usernames.txt and passwords.txt as a ZIP file."""
    db = get_db()
    try:
        data = await asyncio.to_thread(db.credentials.get_unique_credentials)
    except Exception as e:
        get_app_logger().error(f"Error fetching credentials for download: {e}")
        return JSONResponse(content={"error": "Internal server error"}, status_code=500)
    finally:
        db.close_session()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        usernames = "\n".join(data["usernames"])
        passwords = "\n".join(data["passwords"])
        zf.writestr("usernames.txt", usernames)
        zf.writestr("passwords.txt", passwords)

    buf.seek(0)
    return Response(
        content=buf.read(),
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="credentials.zip"',
        },
    )


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
            db.analytics.get_top_ips_paginated,
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
            db.analytics.get_top_paths_paginated,
            page=page,
            page_size=page_size,
            sort_by=sort_by,
            sort_order=sort_order,
            min_count=get_config().dashboard_top_n_min_count,
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
            db.analytics.get_top_user_agents_paginated,
            page=page,
            page_size=page_size,
            sort_by=sort_by,
            sort_order=sort_order,
            min_count=get_config().dashboard_top_n_min_count,
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
            db.analytics.get_attack_types_stats, limit=limit, ip_filter=ip_filter
        )
        set_cached_table(cache_key, result)
        return JSONResponse(content=result, headers=_no_cache_headers())
    except Exception as e:
        get_app_logger().error(f"Error fetching attack types stats: {e}")
        return JSONResponse(content={"error": str(e)}, headers=_no_cache_headers())


@router.get("/api/campaign-stats")
async def campaign_stats(
    request: Request,
    limit: int = Query(12),
    day: str = Query(""),
    days: int = Query(0),
    offset: int = Query(0),
):
    limit = min(max(1, limit), 50)
    window = _campaign_window(day, days=days, offset=offset)
    cache_key = f"api:campaign_stats:{limit}:{day or days or 0}:{offset}"
    cached = get_cached_table(cache_key)
    if cached:
        return JSONResponse(content=cached, headers=_no_cache_headers())

    db = get_db()
    try:
        kwargs = {"limit": limit}
        if window is not None:
            kwargs["start"], kwargs["end"] = window
        clusters = await asyncio.to_thread(db.payloads.get_campaign_clusters, **kwargs)
        campaigns = [
            {
                "id": c["id"],
                "label": (c["rep_hash"] or "")[:8],
                "path": c["path"],
                "top_path": c["top_path"],
                "sample": c["sample"],
                "sources": c["sources"],
                "captures": c["events"],
                "ips": c["ips"],
                "first_seen": (
                    c["first_seen"].isoformat() if c["first_seen"] else None
                ),
                "last_seen": c["last_seen"].isoformat() if c["last_seen"] else None,
            }
            for c in clusters
        ]
        result = {"campaigns": campaigns}
        set_cached_table(cache_key, result)
        return JSONResponse(content=result, headers=_no_cache_headers())
    except Exception as e:
        get_app_logger().error(f"Error fetching campaign stats: {e}")
        return JSONResponse(content={"error": str(e)}, headers=_no_cache_headers())


@router.get("/api/attack-types-daily")
async def attack_types_daily(
    request: Request,
    limit: int = Query(10),
    days: int = Query(30),
    offset_days: int = Query(0),
):
    limit = min(max(1, limit), 20)
    days = min(max(1, days), 90)
    offset_days = max(0, offset_days)

    cache_key = f"api:attack_daily:{limit}:{days}:{offset_days}"
    cached = get_cached_table(cache_key)
    if cached:
        return JSONResponse(content=cached, headers=_no_cache_headers())

    db = get_db()
    try:
        result = await asyncio.to_thread(
            db.analytics.get_attack_types_daily,
            limit=limit,
            days=days,
            offset_days=offset_days,
        )
        set_cached_table(cache_key, result)
        return JSONResponse(content=result, headers=_no_cache_headers())
    except Exception as e:
        get_app_logger().error(f"Error fetching daily attack types: {e}")
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
            db.analytics.get_attack_types_paginated,
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
        raw = await asyncio.to_thread(db.access_logs.get_raw_request_by_id, log_id)
        if raw is None:
            return JSONResponse(
                content={"error": "Raw request not found"}, status_code=404
            )
        return JSONResponse(content={"raw_request": raw}, headers=_no_cache_headers())
    except Exception as e:
        get_app_logger().error(f"Error fetching raw request: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


# Content-Types that are NOT file uploads
_NON_FILE_CONTENT_TYPES = (
    "multipart/",
    "application/json",
    "application/x-www-form-urlencoded",
    "application/xml",
    "application/xhtml+xml",
)

# text/* subtypes that are NOT file uploads (most text/x-* ARE files)
_NON_FILE_TEXT_TYPES = (
    "text/html",
    "text/plain",
    "text/css",
    "text/javascript",
)


def _extract_headers(raw_request: str) -> tuple[str, str, str, str]:
    """Extract headers_text, body, content_type, and path from a raw request.

    Returns (headers_text, body, content_type, path).
    """
    header_end = raw_request.find("\r\n\r\n")
    if header_end == -1:
        return "", "", "", ""
    headers_text = raw_request[:header_end]
    body = raw_request[header_end + 4 :]

    content_type = ""
    path = "/"
    lines = headers_text.split("\r\n")
    if lines:
        parts = lines[0].split(" ")
        if len(parts) >= 2:
            path = parts[1]
    for line in lines[1:]:
        if line.lower().startswith("content-type:"):
            content_type = line.split(":", 1)[1].strip()
            break

    return headers_text, body, content_type, path


def _is_file_content_type(content_type: str) -> bool:
    """Return True if the Content-Type looks like a file (not a form/json/text type)."""
    if not content_type:
        return False
    ct_lower = content_type.lower()
    if any(ct_lower.startswith(p) for p in _NON_FILE_CONTENT_TYPES):
        return False
    if ct_lower.startswith("text/"):
        return not any(ct_lower.startswith(p) for p in _NON_FILE_TEXT_TYPES)
    return True


def _path_to_filename(path: str) -> str:
    """Derive a filename from a request path, e.g. /upload/shell.php -> shell.php."""
    name = path.rsplit("/", 1)[-1] if "/" in path else path
    return name or "attachment"


def _parse_attachments(raw_request: str) -> list[dict]:
    """Parse attachments from a raw HTTP request.

    Handles both multipart/form-data and raw-body file uploads.
    Returns a list of attachment metadata dicts.
    """
    try:
        headers_text, body, content_type, path = _extract_headers(raw_request)
        if not body:
            return []

        # Multipart/form-data: parse individual parts
        if "multipart/form-data" in content_type:
            ct_match = re.search(r"boundary=([^\s;]+)", content_type)
            if not ct_match:
                return []

            if not body.endswith("\r\n"):
                body += "\r\n"

            raw_msg = f"Content-Type: {content_type}\r\n\r\n{body}"
            msg = email.message_from_string(raw_msg, policy=policy.compat32)

            attachments = []
            part_index = 0
            for part in msg.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                disp = part.get("Content-Disposition", "")
                if "attachment" not in disp and "form-data" not in disp:
                    continue
                filename = part.get_filename() or ""
                name = part.get_param("name", header="content-disposition") or ""
                payload = part.get_payload(decode=False) or ""
                attachments.append(
                    {
                        "index": part_index,
                        "name": name,
                        "filename": filename,
                        "content_type": part.get_content_type()
                        or "application/octet-stream",
                        "size": len(payload.encode("utf-8", errors="replace")),
                    }
                )
                part_index += 1
            return attachments

        # Raw body file upload: entire body is one file
        if _is_file_content_type(content_type):
            filename = _path_to_filename(path)
            return [
                {
                    "index": 0,
                    "name": "",
                    "filename": filename,
                    "content_type": content_type.split(";")[0].strip(),
                    "size": len(body.encode("utf-8", errors="replace")),
                }
            ]

        return []
    except Exception as e:
        get_app_logger().error(f"Attachment parse error: {e}")
        return []


def _get_attachment_content(
    raw_request: str, index: int
) -> tuple[str, str, str] | None:
    """Extract a single attachment's content from a raw HTTP request.

    Returns (filename, content_type, content) or None.
    """
    try:
        headers_text, body, content_type, path = _extract_headers(raw_request)
        if not body:
            return None

        # Multipart/form-data: extract specific part
        if "multipart/form-data" in content_type:
            raw_msg = f"Content-Type: {content_type}\r\n\r\n{body}"
            msg = email.message_from_string(raw_msg, policy=policy.compat32)

            current_index = 0
            for part in msg.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                disp = part.get("Content-Disposition", "")
                if "attachment" not in disp and "form-data" not in disp:
                    continue
                if current_index == index:
                    filename = part.get_filename() or "attachment"
                    content = part.get_payload(decode=False) or ""
                    return (
                        filename,
                        part.get_content_type() or "application/octet-stream",
                        content,
                    )
                current_index += 1
            return None

        # Raw body file upload: entire body is the file (only index 0)
        if index == 0 and _is_file_content_type(content_type):
            filename = _path_to_filename(path)
            return filename, content_type.split(";")[0].strip(), body

        return None
    except Exception as e:
        get_app_logger().error(f"Attachment extract error: {e}")
        return None


@router.get("/api/attachments/{log_id:int}")
async def list_attachments(log_id: int, request: Request):
    db = get_db()
    try:
        raw = await asyncio.to_thread(db.access_logs.get_raw_request_by_id, log_id)
        if raw is None:
            return JSONResponse(
                content={"error": "Raw request not found"}, status_code=404
            )
        attachments = _parse_attachments(raw)
        return JSONResponse(
            content={"attachments": attachments}, headers=_no_cache_headers()
        )
    except Exception as e:
        get_app_logger().error(f"Error listing attachments: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.get("/api/attachments/{log_id:int}/download/{index:int}")
async def download_attachment(log_id: int, index: int, request: Request):
    db = get_db()
    try:
        raw = await asyncio.to_thread(db.access_logs.get_raw_request_by_id, log_id)
        if raw is None:
            return JSONResponse(
                content={"error": "Raw request not found"}, status_code=404
            )
        result = _get_attachment_content(raw, index)
        if result is None:
            return JSONResponse(
                content={"error": "Attachment not found"}, status_code=404
            )
        filename, content_type, content = result
        return Response(
            content=content.encode("utf-8", errors="replace"),
            media_type=content_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )
    except Exception as e:
        get_app_logger().error(f"Error downloading attachment: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.get("/api/banlist-sources")
async def banlist_sources(request: Request):
    """Return current banlist source status for dashboard display."""
    from banlist_sync import get_banlist_sources

    sources = get_banlist_sources()
    return JSONResponse(content={"sources": sources})


@router.get("/api/export-ips")
async def export_ips(
    request: Request,
    categories: str = Query(...),
    fwtype: str = Query("raw"),
    merge_banlists: bool = Query(False),
    exclude_cdn: str = Query(""),
):
    valid_categories = {
        "attacker",
        "bad_crawler",
        "regular_user",
        "good_crawler",
        "timed_out",
    }
    cat_list = [c.strip() for c in categories.split(",") if c.strip()]
    if not cat_list or not all(c in valid_categories for c in cat_list):
        return JSONResponse(content={"error": "Invalid categories"}, status_code=400)

    from firewall import FORMATS, format_banlist

    if fwtype.lower() not in FORMATS:
        return JSONResponse(
            content={"error": f"Unknown firewall type: '{fwtype}'"}, status_code=400
        )

    try:
        db = get_db()
        config = request.app.state.config
        server_ip = config.get_server_ip()

        real_cats = [c for c in cat_list if c != "timed_out"]
        ip_set: set[str] = set()
        if real_cats:
            ip_set.update(
                await asyncio.to_thread(db.ip_stats.get_ips_for_export, real_cats)
            )
        if "timed_out" in cat_list:
            ip_set.update(
                await asyncio.to_thread(
                    db.ip_stats.get_timedout_ips, config.ban_duration_seconds
                )
            )

        if merge_banlists:
            from banlist_sync import get_global_banlist

            external = get_global_banlist()
            ip_set.update(external)
            get_app_logger().debug(
                f"[ExportIPs] Merged {len(external)} external banlist IPs"
            )

        ips = list(ip_set)

        from ip_utils import get_cdn_networks, is_cdn_ip, is_valid_public_ip

        public_ips = [ip for ip in ips if is_valid_public_ip(ip, server_ip)]

        providers = [p.strip() for p in exclude_cdn.split(",") if p.strip()]
        if providers:
            cdn_nets = await asyncio.to_thread(get_cdn_networks, providers)
            before = len(public_ips)
            public_ips = [ip for ip in public_ips if not is_cdn_ip(ip, cdn_nets)]
            get_app_logger().debug(
                f"[ExportIPs] Excluded {before - len(public_ips)} CDN IPs"
            )

        content = format_banlist(fwtype, public_ips)

        cat_label = "_".join(sorted(cat_list))
        filename = f"{fwtype}_{cat_label}_export.txt"

        return Response(
            content=content,
            status_code=200,
            media_type="text/plain",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(content.encode("utf-8"))),
            },
        )
    except Exception as e:
        get_app_logger().error(f"Error exporting IPs: {e}")
        return JSONResponse(content={"error": "Internal server error"}, status_code=500)


@router.post("/api/delete-generated-pages", dependencies=[Depends(require_auth)])
async def delete_generated_pages(
    request: Request,
    before_date: str = Query(None),
    delete_all: str = Query(None),
    ids: str = Query(None),
):
    """Delete generated deception pages from database.

    Requires authentication. Can delete:
    - All pages (delete_all=true)
    - Pages created before a specific date (before_date=YYYY-MM-DD)
    - Specific pages by ID (ids=id1,id2,id3)
    """
    db = get_db()
    deleted_count = 0

    try:
        if delete_all == "true":
            # Delete all generated pages
            deleted_count = db.generated_pages.delete_all()
            get_app_logger().info(
                f"[DECEPTION] Deleted all {deleted_count} generated pages"
            )
            message = f"Deleted {deleted_count} generated pages"

        elif before_date:
            # Delete pages older than the specified date
            # Expected format: YYYY-MM-DD
            deleted_count = db.generated_pages.delete_before(before_date)
            get_app_logger().info(
                f"[DECEPTION] Deleted {deleted_count} pages created before {before_date}"
            )
            message = f"Deleted {deleted_count} pages created before {before_date}"

        elif ids:
            # Delete specific pages by path
            page_ids = [id.strip() for id in ids.split(",") if id.strip()]
            deleted_count = db.generated_pages.delete_by_ids(page_ids)
            get_app_logger().info(f"[DECEPTION] Deleted {deleted_count} selected pages")
            message = f"Deleted {deleted_count} selected page(s)"

        else:
            return JSONResponse(
                content={"error": "Please specify delete_all, before_date, or ids"},
                status_code=400,
            )

        # Return the updated deception panel
        from dependencies import get_templates
        from routes.htmx import _dashboard_path

        templates = get_templates()
        return templates.TemplateResponse(
            request,
            "dashboard/partials/deception_panel_with_message.html",
            {
                "dashboard_path": _dashboard_path(request),
                "message": message,
                "deleted_count": deleted_count,
            },
        )

    except ValueError as e:
        get_app_logger().error(f"[DECEPTION] Delete error: {e}")
        return JSONResponse(
            content={"error": str(e)},
            status_code=400,
        )
    except Exception as e:
        get_app_logger().error(f"[DECEPTION] Unexpected error deleting pages: {e}")
        return JSONResponse(
            content={"error": "Internal server error"},
            status_code=500,
        )


@router.get("/api/download-generated-page", dependencies=[Depends(require_auth)])
async def download_generated_page(
    request: Request,
    path: str = Query(...),
):
    """Download a generated deception page as an HTML file."""
    import base64

    from models import GeneratedPage

    db = get_db()
    try:
        session = db.session
        page = session.query(GeneratedPage).filter(GeneratedPage.path == path).first()
        if not page:
            return JSONResponse(content={"error": "Page not found"}, status_code=404)

        html_content = base64.b64decode(page.html_content_b64).decode("utf-8")
        # Build a safe filename from the path (convert / to __ for round-trip compatibility)
        safe_name = path.strip("/").replace("/", "__") or "index"
        safe_name = safe_name[:100]
        if not safe_name.endswith(".html"):
            safe_name += ".html"

        return Response(
            content=html_content,
            media_type="text/html",
            headers={
                "Content-Disposition": f'attachment; filename="{safe_name}"',
            },
        )
    except Exception as e:
        get_app_logger().error(f"[DECEPTION] Download error: {e}")
        return JSONResponse(content={"error": "Internal server error"}, status_code=500)
    finally:
        db.close_session()


@router.post("/api/download-generated-pages-zip", dependencies=[Depends(require_auth)])
async def download_generated_pages_zip(
    request: Request,
    paths: str = Query(None),
    before_date: str = Query(None),
    select_all: bool = Query(False),
):
    """Download multiple generated deception pages as a ZIP file."""
    from models import GeneratedPage

    db = get_db()
    try:
        session = db.session
        pages_to_download = []

        if select_all:
            # Download all pages
            pages_to_download = session.query(GeneratedPage).all()
            page_paths = [p.path for p in pages_to_download]
            get_app_logger().info(
                f"[DECEPTION] Download all: found {len(pages_to_download)} pages - Paths: {page_paths}"
            )
        elif paths:
            # Parse paths (comma-separated)
            path_list = [p.strip() for p in paths.split(",") if p.strip()]
            if not path_list:
                return JSONResponse(
                    content={"error": "No paths provided"}, status_code=400
                )

            get_app_logger().debug(
                f"[DECEPTION] Download requested for paths: {path_list}"
            )

            # Query pages by paths
            for path in path_list:
                page = (
                    session.query(GeneratedPage)
                    .filter(GeneratedPage.path == path)
                    .first()
                )
                if page:
                    pages_to_download.append(page)
                else:
                    get_app_logger().debug(f"[DECEPTION] Path not found: {path}")

        elif before_date:
            # Query pages by date
            try:
                pages_to_download = db.generated_pages.get_before(before_date)
                get_app_logger().debug(
                    f"[DECEPTION] Download by date {before_date}: found {len(pages_to_download)} pages"
                )
            except ValueError as e:
                return JSONResponse(content={"error": str(e)}, status_code=400)
        else:
            return JSONResponse(
                content={
                    "error": "Please specify either select_all, paths, or before_date"
                },
                status_code=400,
            )

        if not pages_to_download:
            return JSONResponse(
                content={"error": "No pages found to download"}, status_code=404
            )

        # Create ZIP file in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for page in pages_to_download:
                try:
                    html_content = base64.b64decode(page.html_content_b64).decode(
                        "utf-8"
                    )
                    # Build a safe filename from the path (convert / to __ for round-trip compatibility)
                    safe_name = page.path.strip("/").replace("/", "__") or "index"
                    safe_name = safe_name[:100]  # Truncate filename for safety
                    if not safe_name.endswith(".html"):
                        safe_name += ".html"

                    # Add file to ZIP (encode content to bytes)
                    zip_file.writestr(safe_name, html_content.encode("utf-8"))
                except Exception as e:
                    get_app_logger().warning(
                        f"[DECEPTION] Error adding page {page.path} to ZIP: {e}"
                    )
                    continue

        zip_buffer.seek(0)
        return Response(
            content=zip_buffer.getvalue(),
            media_type="application/zip",
            headers={
                "Content-Disposition": 'attachment; filename="deception_pages.zip"',
            },
        )
    except Exception as e:
        get_app_logger().error(f"[DECEPTION] ZIP download error: {e}")
        return JSONResponse(content={"error": "Internal server error"}, status_code=500)
    finally:
        db.close_session()


class UploadPageRequest(BaseModel):
    path: str
    content: str


class UploadBulkPagesRequest(BaseModel):
    pages: dict  # { path: content, ... }


@router.post("/api/upload-generated-page", dependencies=[Depends(require_auth)])
async def upload_generated_page(request: Request, body: UploadPageRequest):
    """Upload a custom page to serve as a deception page."""
    import base64
    from datetime import datetime

    from models import GeneratedPage

    path = body.path.strip()
    content = body.content

    if not path or not content:
        return JSONResponse(
            content={"error": "Path and content are required"}, status_code=400
        )

    # Convert double underscores to slashes (path encoding from filenames)
    path = path.replace("__", "/")

    # Ensure path starts with /
    if not path.startswith("/"):
        path = "/" + path

    # Strip file extensions for consistency with honeypot search
    allowed_exts = (".html", ".htm", ".xml", ".json", ".txt", ".css", ".js")
    for ext in allowed_exts:
        if path.endswith(ext):
            path = path[: -len(ext)]
            break

    db = get_db()
    try:
        session = db.session
        html_b64 = base64.b64encode(content.encode("utf-8")).decode("utf-8")

        existing = (
            session.query(GeneratedPage).filter(GeneratedPage.path == path).first()
        )
        if existing:
            existing.html_content_b64 = html_b64
            existing.last_accessed = datetime.now()
            get_app_logger().info(f"[DECEPTION] Updated uploaded page: {path}")
        else:
            page = GeneratedPage(
                path=path,
                html_content_b64=html_b64,
                created_at=datetime.now(),
                last_accessed=datetime.now(),
                access_count=0,
            )
            session.add(page)
            get_app_logger().info(f"[DECEPTION] Uploaded new custom page: {path}")

        session.commit()
        return JSONResponse(content={"ok": True, "path": path})

    except Exception as e:
        session.rollback()
        get_app_logger().error(f"[DECEPTION] Upload error: {e}")
        return JSONResponse(content={"error": "Internal server error"}, status_code=500)
    finally:
        db.close_session()


@router.post("/api/upload-generated-pages-bulk", dependencies=[Depends(require_auth)])
async def upload_generated_pages_bulk(request: Request, body: UploadBulkPagesRequest):
    """Upload multiple deception pages from a ZIP file."""
    import base64
    from datetime import datetime

    from models import GeneratedPage

    if not body.pages or not isinstance(body.pages, dict):
        return JSONResponse(content={"error": "No pages provided"}, status_code=400)

    db = get_db()
    try:
        session = db.session
        uploaded_count = 0
        errors = []

        for path, content in body.pages.items():
            try:
                path = path.strip()
                if not path or not content:
                    continue

                # Convert double underscores to slashes (path encoding from filenames)
                path = path.replace("__", "/")

                # Ensure path starts with /
                if not path.startswith("/"):
                    path = "/" + path

                # Strip file extensions for consistency with honeypot search
                allowed_exts = (".html", ".htm", ".xml", ".json", ".txt", ".css", ".js")
                for ext in allowed_exts:
                    if path.endswith(ext):
                        path = path[: -len(ext)]
                        break

                html_b64 = base64.b64encode(content.encode("utf-8")).decode("utf-8")

                existing = (
                    session.query(GeneratedPage)
                    .filter(GeneratedPage.path == path)
                    .first()
                )
                if existing:
                    existing.html_content_b64 = html_b64
                    existing.last_accessed = datetime.now()
                else:
                    page = GeneratedPage(
                        path=path,
                        html_content_b64=html_b64,
                        created_at=datetime.now(),
                        last_accessed=datetime.now(),
                        access_count=0,
                    )
                    session.add(page)

                uploaded_count += 1
            except Exception as e:
                errors.append((path, str(e)))
                continue

        session.commit()
        get_app_logger().info(
            f"[DECEPTION] Bulk uploaded {uploaded_count} pages from ZIP"
        )
        return JSONResponse(
            content={
                "ok": True,
                "uploaded": uploaded_count,
                "errors": errors,
            }
        )

    except Exception as e:
        session.rollback()
        get_app_logger().error(f"[DECEPTION] Bulk upload error: {e}")
        return JSONResponse(content={"error": "Internal server error"}, status_code=500)
    finally:
        db.close_session()


# ── Webhooks API ──────────────────────────────────────────────────────


class CloudflareSaveRequest(BaseModel):
    account_id: str
    auth_token: str
    list_name: str = "krawl_banlist"
    list_description: str = "IPs banned by Krawl honeypot"
    sync_interval_minutes: int = 30
    categories: list[str] = ["attacker"]
    enabled: bool = False
    zone_id: str = ""
    rule_action: str = "block"

    @validator("account_id")
    def validate_account_id(cls, v):
        v = v.strip()
        if not re.fullmatch(r"[0-9a-f]{32}", v):
            raise ValueError(
                "Account ID must be exactly 32 hex characters (e.g. 1a2b3c4d5e6f7890abcdef1234567890)"
            )
        return v

    @validator("zone_id")
    def validate_zone_id(cls, v, values):
        v = v.strip()
        if v and not re.fullmatch(r"[0-9a-f]{32}", v):
            raise ValueError(
                "Zone ID must be exactly 32 hex characters (e.g. 1a2b3c4d5e6f7890abcdef1234567890)"
            )
        if v and v == values.get("account_id"):
            raise ValueError(
                "Zone ID cannot be the same as the Account ID - copy it from the zone's Overview page"
            )
        return v


@router.post("/api/webhooks/cloudflare/save", dependencies=[Depends(require_auth)])
async def webhook_cloudflare_save(request: Request, body: CloudflareSaveRequest):
    from webhooks import (
        cf_test_connection,
        get_cloudflare_config,
        save_cloudflare_config,
    )

    account_id = body.account_id.strip()
    auth_token = body.auth_token.strip()

    # Test the connection first — fail fast
    test_result = cf_test_connection(account_id, auth_token)
    if not test_result.get("success"):
        errors = [e.get("message", str(e)) for e in test_result.get("errors", [])]
        return JSONResponse(
            content={"ok": False, "error": f"Connection failed: {errors}"},
            status_code=400,
        )

    existing = get_cloudflare_config()

    # Clear list_id if account_id changed — list from old account won't work
    existing_account = existing.get("account_id", "")
    list_id = existing.get("list_id") if existing_account == account_id else None

    cf_config = {
        "enabled": body.enabled,
        "account_id": account_id,
        "auth_token": auth_token,
        "list_id": list_id,
        "list_name": body.list_name.strip() or "krawl_banlist",
        "list_description": body.list_description.strip()
        or "IPs banned by Krawl honeypot",
        "sync_interval_minutes": max(1, body.sync_interval_minutes),
        "categories": body.categories or ["attacker"],
        "zone_id": body.zone_id.strip(),
        "rule_action": body.rule_action,
        "last_sync": existing.get("last_sync"),
        "last_sync_status": existing.get("last_sync_status"),
        "last_sync_error": existing.get("last_sync_error"),
    }

    save_cloudflare_config(cf_config)
    get_app_logger().info("[Webhooks] CloudFlare config saved")

    # If no list_id yet, try to create the CF list
    cf_list_error = None
    if not cf_config["list_id"]:
        from webhooks import cf_create_list

        try:
            result = cf_create_list(
                account_id,
                auth_token,
                cf_config["list_name"],
                cf_config["list_description"],
            )
            get_app_logger().info(
                f"[Webhooks] CF create list response: success={result.get('success')} errors={result.get('errors', [])}"
            )
            if result.get("success"):
                cf_config["list_id"] = result["result"]["id"]
                save_cloudflare_config(cf_config)
                get_app_logger().info(
                    f"[Webhooks] Created CF list: {cf_config['list_id']}"
                )
            else:
                errors = [e.get("message", str(e)) for e in result.get("errors", [])]
                cf_list_error = f"Saved. Failed to create CF list: {errors}"
                get_app_logger().warning(f"[Webhooks] {cf_list_error}")
        except Exception as e:
            cf_list_error = f"Saved. CF list creation error: {e}"
            get_app_logger().error(f"[Webhooks] {cf_list_error}")

    resp = {
        "ok": True,
        "list_id": cf_config["list_id"],
        "list_name": cf_config["list_name"],
    }

    # Create the WAF rule referencing the banlist if a zone_id is configured
    if cf_config["zone_id"]:
        from webhooks import cf_ensure_custom_rule, cf_get_zone

        try:
            zone_info = cf_get_zone(cf_config["zone_id"], auth_token)
            if zone_info.get("success") and zone_info.get("result", {}).get("name"):
                cf_config["zone_name"] = zone_info["result"]["name"]
            rule_result = cf_ensure_custom_rule(
                cf_config["zone_id"],
                auth_token,
                cf_config["list_name"],
                cf_config["rule_action"],
            )
            resp["rule_created"] = rule_result.get("created", False)
            resp["rule_exists"] = rule_result.get("exists", False)
            cf_config["waf_rule_created"] = bool(
                rule_result.get("created") or rule_result.get("exists")
            )
            resp["zone_name"] = cf_config.get("zone_name", "")
            save_cloudflare_config(cf_config)
            if rule_result.get("error"):
                cf_list_error = cf_list_error or rule_result["error"]
                get_app_logger().warning(f"[Webhooks] {rule_result['error']}")
        except Exception as e:
            cf_list_error = cf_list_error or f"WAF rule creation error: {e}"
            get_app_logger().error(f"[Webhooks] {cf_list_error}")

    if cf_list_error:
        resp["warning"] = cf_list_error
    return JSONResponse(content=resp)


@router.post("/api/webhooks/cloudflare/sync", dependencies=[Depends(require_auth)])
async def webhook_cloudflare_sync(request: Request):
    from datetime import datetime

    from webhooks import (
        get_cloudflare_config,
        save_cloudflare_config,
        sync_banlist_to_cloudflare,
    )

    cf_config = get_cloudflare_config()
    if not cf_config.get("account_id") or not cf_config.get("auth_token"):
        return JSONResponse(
            content={"error": "CloudFlare not configured"},
            status_code=400,
        )

    result = sync_banlist_to_cloudflare(cf_config)

    # Update last_sync info
    cf_config["last_sync"] = datetime.now(UTC).isoformat()
    cf_config["last_sync_status"] = result.get("status", "error")
    cf_config["last_sync_error"] = result.get("error")
    save_cloudflare_config(cf_config)

    if result.get("status") == "ok":
        return JSONResponse(
            content={
                "ok": True,
                "count": result.get("count", 0),
                "list_id": result.get("list_id"),
            }
        )
    return JSONResponse(
        content={"error": result.get("error", "Sync failed")},
        status_code=400,
    )


@router.get("/api/webhooks/status", dependencies=[Depends(require_auth)])
async def webhook_status(request: Request):
    from webhooks import get_cloudflare_config, save_cloudflare_config

    cf = get_cloudflare_config()

    # Backfill zone_name once so the dashboard link can use the zone domain
    zone_id = cf.get("zone_id", "")
    if zone_id and not cf.get("zone_name"):
        from webhooks import cf_get_zone

        zone_info = cf_get_zone(zone_id, cf.get("auth_token", ""))
        if zone_info.get("success") and zone_info.get("result", {}).get("name"):
            cf["zone_name"] = zone_info["result"]["name"]
            save_cloudflare_config(cf)

    return JSONResponse(
        content={
            "cloudflare": {
                "enabled": cf.get("enabled", False),
                "configured": bool(cf.get("account_id") and cf.get("auth_token")),
                "account_id": cf.get("account_id", ""),
                "auth_token": cf.get("auth_token", ""),
                "list_id": cf.get("list_id"),
                "list_name": cf.get("list_name", "krawl_banlist"),
                "sync_interval_minutes": cf.get("sync_interval_minutes", 30),
                "categories": cf.get("categories", ["attacker"]),
                "zone_id": zone_id,
                "zone_name": cf.get("zone_name", ""),
                "rule_action": cf.get("rule_action", "block"),
                "waf_rule_created": cf.get("waf_rule_created", False),
                "last_sync": cf.get("last_sync"),
                "last_sync_status": cf.get("last_sync_status"),
                "last_sync_error": cf.get("last_sync_error"),
            }
        }
    )


@router.delete("/api/webhooks/cloudflare/config", dependencies=[Depends(require_auth)])
async def webhook_cloudflare_delete(request: Request):
    from webhooks import load_config, save_config

    cfg = load_config()
    cfg["cloudflare"] = {
        "enabled": False,
        "account_id": "",
        "auth_token": "",
        "list_id": None,
    }
    save_config(cfg)
    return JSONResponse(content={"ok": True})


# ---------------------------------------------------------------------------
# Maintenance panel: run the scheduled tasks on demand
# ---------------------------------------------------------------------------
# TasksMaster already discovers every module under src/tasks/ exposing
# TASK_CONFIG + main(), and holds its schedule. These two endpoints are a thin
# authenticated view over that registry — there is no separate job runner, and
# adding a task file is all it takes to make it appear in the panel.

_RUN_LOCK_TTL = 3600  # a stuck task must not block its own next run forever


def _acquire_run_lock(name: str) -> bool:
    """Claim the right to run `name`. False when it is already running.

    One click must not start the task on every replica, and a second click must
    not start it twice on this one. Both are the shared cross-pod lease; unlike
    the scheduler's use of it, this one is released on completion.
    """
    import task_lock

    return task_lock.claim(name, _RUN_LOCK_TTL)


def _release_run_lock(name: str) -> None:
    """Free the task for another manual run now that this one has finished."""
    import task_lock

    task_lock.release(name)


def _is_running(name: str) -> bool:
    """True while a manual run of `name` is in flight anywhere in the cluster."""
    import task_lock

    return task_lock.is_held(name)


@router.get("/api/tasks", dependencies=[Depends(require_auth)])
async def list_tasks():
    """List every discovered task with its schedule and current state."""
    from tasks_master import get_tasksmaster

    tm = get_tasksmaster()
    next_runs = {}
    try:
        for job in tm.scheduler.get_jobs():
            next_runs[job.name] = (
                job.next_run_time.isoformat() if job.next_run_time else None
            )
    except Exception as e:
        get_app_logger().error(f"Could not read scheduled job times: {e}")

    tasks = []
    for t in tm.tasks:
        name = t.get("name")
        entry = {
            "name": name,
            "filename": t.get("filename"),
            "cron": t.get("cron"),
            "interval_seconds": t.get("interval_seconds"),
            "enabled": bool(t.get("enabled")),
            "next_run": next_runs.get(name),
            "running": _is_running(name),
            "options": None,
        }
        # The purge task is the only one taking arguments; surface its targets
        # so the panel can render them as checkboxes.
        if t.get("filename") == "purge.py":
            from tasks.purge import PURGE_TARGETS

            entry["options"] = [
                {"key": k, "label": v} for k, v in PURGE_TARGETS.items()
            ]
        tasks.append(entry)

    return JSONResponse(content={"tasks": tasks}, headers=_no_cache_headers())


class RunTaskRequest(BaseModel):
    name: str
    targets: list[str] | None = None


@router.post("/api/tasks/run", dependencies=[Depends(require_auth)])
async def run_task(body: RunTaskRequest):
    """Run one discovered task now, in a worker thread.

    Only names already present in the TasksMaster registry are accepted, so
    this cannot be used to import an arbitrary module.
    """
    import importlib
    import os

    from tasks_master import get_tasksmaster

    task = next(
        (t for t in get_tasksmaster().tasks if t.get("name") == body.name), None
    )
    if task is None:
        return JSONResponse(content={"error": "Unknown task"}, status_code=404)

    if not _acquire_run_lock(body.name):
        return JSONResponse(
            content={"error": "Task is already running"}, status_code=409
        )

    module_name = os.path.splitext(task["filename"])[0]
    try:
        module = importlib.import_module(f"tasks.{module_name}")
        kwargs = {"targets": body.targets} if body.targets is not None else {}
        get_app_logger().info(f"Manual run of task {body.name} requested")
        started = time.monotonic()
        result = await asyncio.to_thread(lambda: module.main(**kwargs))
        elapsed = round(time.monotonic() - started, 2)
        get_app_logger().info(f"Manual run of task {body.name} finished in {elapsed}s")
        return JSONResponse(
            content={
                "ok": True,
                "name": body.name,
                "elapsed_seconds": elapsed,
                "result": result if isinstance(result, dict) else None,
            }
        )
    except Exception as e:
        get_app_logger().error(f"Manual run of task {body.name} failed: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)
    finally:
        _release_run_lock(body.name)


# ---------------------------------------------------------------------------
# Settings panel: the running configuration, read-only
# ---------------------------------------------------------------------------
# Config is a flat dataclass whose field names already carry the config.yaml
# section as a prefix (postgres_*, ai_*, map_*), so both the grouping and the
# redaction can be derived from the field name instead of a hand-kept map that
# drifts the moment someone adds a field.

# Substrings that make a field secret. This is the important half of the
# redaction: an explicit list alone fails open — a secret added to Config next
# year would leak until someone remembered to list it here. The pattern
# catches it by default, and _SENSITIVE_FIELDS only covers what the pattern
# cannot infer from the name.
_SENSITIVE_PATTERNS = ("password", "secret", "api_key", "token")

# The escape hatch for a secret the pattern would miss. Everything here is
# also caught by _SENSITIVE_PATTERNS today; the entry stays because a canary
# URL being secret is not obvious from its name, and a future rename should
# not quietly turn it into a visible field.
_SENSITIVE_FIELDS = frozenset(
    {
        "canary_token_url",  # the canary's callback URL is a live tripwire
    }
)

# Fields the pattern flags but that hold no secret — a retry count and a
# boolean. Redacting them would hide useful state behind a "Set" badge that
# says nothing. Keep this list short: every entry is a hole in the backstop.
_NOT_SENSITIVE_FIELDS = frozenset(
    {
        "canary_token_tries",
        "dashboard_password_generated",
        "dashboard_secret_path_generated",
    }
)

# Generated at startup when config.yaml leaves them unset, so the running
# value is not a choice anyone made and must not be badged as one. Each maps
# to the flag that records whether it was generated this run.
_GENERATED_WHEN = {
    "dashboard_secret_path": "dashboard_secret_path_generated",
    "dashboard_password": "dashboard_password_generated",
}

# Derived state, not settings: no config.yaml key sets these, so "changed from
# the default" is not a thing that can be true of them. Shown, never badged.
_DERIVED_FIELDS = frozenset(_GENERATED_WHEN.values())

# Section order. Anything whose name starts with "<prefix>_" lands in that
# section; whatever is left over goes to "server", which is where the
# ungrouped top-level knobs (mode, port, delay, log_level) already belong.
_CONFIG_SECTIONS = (
    "server",
    "dashboard",
    "database",
    "postgres",
    "redis",
    "crawl",
    "analyzer",
    "tarpit",
    "ai",
    "map",
    "banlist",
    "backups",
    "deception",
    "ipv6",
    "metrics",
    "links",
    "canary",
)

# Every section except the catch-all is also a field-name prefix to match on.
_SECTION_PREFIXES = tuple(s for s in _CONFIG_SECTIONS if s != "server")


# Fields whose config.yaml section the name prefix cannot reveal: the
# `analyzer:` and `crawl:` blocks are flattened into bare names.
_FIELD_SECTIONS = {
    "http_risky_methods_threshold": "analyzer",
    "violated_robots_threshold": "analyzer",
    "uneven_request_timing_threshold": "analyzer",
    "uneven_request_timing_time_window_seconds": "analyzer",
    "user_agents_used_threshold": "analyzer",
    "attack_urls_threshold": "analyzer",
    "max_pages_limit": "crawl",
    "infinite_pages_for_malicious": "crawl",
    "ban_duration_seconds": "crawl",
}


def _is_sensitive(name: str) -> bool:
    """True when a field's value must never leave the server."""
    if name in _NOT_SENSITIVE_FIELDS:
        return False
    if name in _SENSITIVE_FIELDS:
        return True
    return any(p in name for p in _SENSITIVE_PATTERNS)


def _config_section(name: str) -> tuple[str, str]:
    """Split a flat field name into (section, label within that section)."""
    if name in _FIELD_SECTIONS:
        return _FIELD_SECTIONS[name], name
    for prefix in _SECTION_PREFIXES:
        if name.startswith(f"{prefix}_"):
            return prefix, name[len(prefix) + 1 :]
    return "server", name


def _is_unset(value) -> bool:
    """True for every way this config says "no value"."""
    return value is None or value == "" or value == [] or value == ()


def _json_safe(value):
    """Render a config value in a form JSON can carry and a table can show."""
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, (str, int, float, bool, list, dict)) or value is None:
        return value
    return str(value)


def _config_fields(cfg) -> list[dict]:
    """Serialize a Config into the panel's rows, with every secret redacted.

    Split out from the endpoint so the tests exercise this exact code rather
    than a copy of it that can drift.
    """
    import dataclasses
    import os

    from config import Config
    from config import __get_env_from_config as env_name_for

    defaults = Config()
    fields = []
    for f in dataclasses.fields(cfg):
        name = f.name
        # Private bookkeeping (_server_ip, _server_ip_resolved) is not config.
        if name.startswith("_"):
            continue

        value = getattr(cfg, name)
        env_var = env_name_for(name)
        default = getattr(defaults, name, None)
        sensitive = _is_sensitive(name)

        # Provenance. An env override is provable; beyond that all we can
        # honestly say is whether the value still matches the built-in
        # default, because from_yaml does not keep the raw document and the
        # nested-to-flat mapping is hand-written per field.
        #
        # Unset is unset: a default of None against a config.yaml "" (or a
        # bare key, which YAML reads as None) is the same thing to a reader
        # but not to ==, and comparing raw badged untouched settings "custom".
        generated_flag = _GENERATED_WHEN.get(name)
        if name in _DERIVED_FIELDS:
            source = "default"
        elif env_var in os.environ:
            source = "env"
        elif generated_flag and getattr(cfg, generated_flag, False):
            # Generated this run because config.yaml left it unset.
            source = "default"
        elif _is_unset(value) and _is_unset(default):
            source = "default"
        elif value != default:
            source = "custom"
        else:
            source = "default"

        section, label = _config_section(name)
        entry = {
            "key": name,
            "label": label,
            "section": section,
            "source": source,
            "env_var": env_var,
            "sensitive": sensitive,
        }
        if sensitive:
            # Truthiness, not the value: "" and None are unset, anything else
            # is set. The value never enters the response, so it is not in the
            # page source either.
            entry["set"] = bool(value)
        else:
            entry["value"] = _json_safe(value)
        fields.append(entry)

    # Group by section, but keep declaration order inside one — it mirrors
    # config.yaml, where provider/base_url/api_key/model sit together. Sorting
    # by name would scatter them.
    order = {s: i for i, s in enumerate(_CONFIG_SECTIONS)}
    fields.sort(key=lambda e: order.get(e["section"], len(order)))
    return fields


@router.get("/api/config", dependencies=[Depends(require_auth)])
async def get_current_config():
    """The running configuration, with every secret redacted.

    Sensitive fields report only whether they are set — that is the question
    the panel exists to answer ("is my AI key actually loaded?") and it
    discloses nothing.
    """
    cfg = get_config()

    sections = []
    for entry in _config_fields(cfg):
        if not sections or sections[-1]["name"] != entry["section"]:
            sections.append({"name": entry["section"], "fields": []})
        sections[-1]["fields"].append(entry)

    return JSONResponse(
        content={"sections": sections, "mode": cfg.mode},
        headers=_no_cache_headers(),
    )
