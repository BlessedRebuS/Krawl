#!/usr/bin/env python3

"""
HTMX fragment endpoints.
Server-rendered HTML partials for table pagination, sorting, IP details, and search.
"""

import asyncio

from fastapi import APIRouter, Request, Response, Query
from fastapi.responses import HTMLResponse

from dependencies import get_db, get_templates
from routes.api import verify_auth
from config import get_config
from dashboard_cache import get_cached, is_warm, get_cached_table, set_cached_table

router = APIRouter()


def _dashboard_path(request: Request) -> str:
    config = request.app.state.config
    return "/" + config.dashboard_secret_path.lstrip("/")


# ── Honeypot Triggers ────────────────────────────────────────────────


@router.get("/htmx/honeypot")
async def htmx_honeypot(
    request: Request,
    page: int = Query(1),
    sort_by: str = Query("count"),
    sort_order: str = Query("desc"),
):
    page = max(1, page)
    cache_key = f"honeypot:{page}:{sort_by}:{sort_order}"
    cached = get_cached_table(cache_key)
    if cached:
        result = cached
    else:
        db = get_db()
        result = await asyncio.to_thread(
            db.get_honeypot_paginated,
            page=page,
            page_size=5,
            sort_by=sort_by,
            sort_order=sort_order,
        )
        set_cached_table(cache_key, result)

    templates = get_templates()
    return templates.TemplateResponse(
        request,
        "dashboard/partials/honeypot_table.html",
        {
            "dashboard_path": _dashboard_path(request),
            "items": result["honeypots"],
            "pagination": result["pagination"],
            "sort_by": sort_by,
            "sort_order": sort_order,
        },
    )


# ── Top IPs ──────────────────────────────────────────────────────────


@router.get("/htmx/top-ips")
async def htmx_top_ips(
    request: Request,
    page: int = Query(1),
    sort_by: str = Query("count"),
    sort_order: str = Query("desc"),
):
    # Serve from cache on default first-page request
    cached = (
        get_cached("top_ips")
        if (
            get_config().dashboard_cache_warmup
            and page == 1
            and sort_by == "count"
            and sort_order == "desc"
            and is_warm()
        )
        else None
    )
    if cached:
        result = cached
    else:
        db = get_db()
        result = await asyncio.to_thread(
            db.get_top_ips_paginated,
            page=max(1, page),
            page_size=8,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    templates = get_templates()
    return templates.TemplateResponse(
        request,
        "dashboard/partials/top_ips_table.html",
        {
            "dashboard_path": _dashboard_path(request),
            "items": result["ips"],
            "pagination": result["pagination"],
            "sort_by": sort_by,
            "sort_order": sort_order,
        },
    )


# ── Top Paths ────────────────────────────────────────────────────────


@router.get("/htmx/top-paths")
async def htmx_top_paths(
    request: Request,
    page: int = Query(1),
    sort_by: str = Query("count"),
    sort_order: str = Query("desc"),
):
    cached = (
        get_cached("top_paths")
        if (
            get_config().dashboard_cache_warmup
            and page == 1
            and sort_by == "count"
            and sort_order == "desc"
            and is_warm()
        )
        else None
    )
    if cached:
        result = cached
    else:
        db = get_db()
        result = await asyncio.to_thread(
            db.get_top_paths_paginated,
            page=max(1, page),
            page_size=5,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    templates = get_templates()
    return templates.TemplateResponse(
        request,
        "dashboard/partials/top_paths_table.html",
        {
            "dashboard_path": _dashboard_path(request),
            "items": result["paths"],
            "pagination": result["pagination"],
            "sort_by": sort_by,
            "sort_order": sort_order,
        },
    )


# ── Top User-Agents ─────────────────────────────────────────────────


@router.get("/htmx/top-ua")
async def htmx_top_ua(
    request: Request,
    page: int = Query(1),
    sort_by: str = Query("count"),
    sort_order: str = Query("desc"),
):
    cached = (
        get_cached("top_ua")
        if (
            get_config().dashboard_cache_warmup
            and page == 1
            and sort_by == "count"
            and sort_order == "desc"
            and is_warm()
        )
        else None
    )
    if cached:
        result = cached
    else:
        db = get_db()
        result = await asyncio.to_thread(
            db.get_top_user_agents_paginated,
            page=max(1, page),
            page_size=5,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    templates = get_templates()
    return templates.TemplateResponse(
        request,
        "dashboard/partials/top_ua_table.html",
        {
            "dashboard_path": _dashboard_path(request),
            "items": result["user_agents"],
            "pagination": result["pagination"],
            "sort_by": sort_by,
            "sort_order": sort_order,
        },
    )


# ── Attackers ────────────────────────────────────────────────────────


@router.get("/htmx/attackers")
async def htmx_attackers(
    request: Request,
    page: int = Query(1),
    sort_by: str = Query("total_requests"),
    sort_order: str = Query("desc"),
):
    page = max(1, page)
    cache_key = f"attackers:{page}:{sort_by}:{sort_order}"
    cached = get_cached_table(cache_key)
    if cached:
        result = cached
    else:
        db = get_db()
        result = await asyncio.to_thread(
            db.get_attackers_paginated,
            page=page,
            page_size=25,
            sort_by=sort_by,
            sort_order=sort_order,
        )
        set_cached_table(cache_key, result)

    # Normalize pagination key (DB returns total_attackers, template expects total)
    pagination = result["pagination"]
    if "total_attackers" in pagination and "total" not in pagination:
        pagination["total"] = pagination["total_attackers"]

    templates = get_templates()
    return templates.TemplateResponse(
        request,
        "dashboard/partials/attackers_table.html",
        {
            "dashboard_path": _dashboard_path(request),
            "items": result["attackers"],
            "pagination": pagination,
            "sort_by": sort_by,
            "sort_order": sort_order,
        },
    )


# ── Access logs by ip ────────────────────────────────────────────────────────


@router.get("/htmx/access-logs")
async def htmx_access_logs_by_ip(
    request: Request,
    page: int = Query(1),
    sort_by: str = Query("total_requests"),
    sort_order: str = Query("desc"),
    ip_filter: str = Query(None),
):
    page = max(1, page)
    cache_key = f"access_logs:{page}:{sort_order}:{ip_filter or ''}"
    cached = get_cached_table(cache_key)
    if cached:
        result = cached
    else:
        db = get_db()
        result = await asyncio.to_thread(
            db.get_access_logs_paginated,
            page=page,
            page_size=25,
            ip_filter=ip_filter,
            sort_order=sort_order if sort_order in ("asc", "desc") else "desc",
        )
        set_cached_table(cache_key, result)

    # Normalize pagination key (DB returns total_logs, template expects total)
    pagination = result["pagination"]
    if "total_logs" in pagination and "total" not in pagination:
        pagination["total"] = pagination["total_logs"]

    templates = get_templates()
    return templates.TemplateResponse(
        request,
        "dashboard/partials/access_by_ip_table.html",
        {
            "dashboard_path": _dashboard_path(request),
            "items": result["access_logs"],
            "pagination": pagination,
            "sort_by": sort_by,
            "sort_order": sort_order,
            "ip_filter": ip_filter,
        },
    )


# ── Credentials ──────────────────────────────────────────────────────


@router.get("/htmx/credentials")
async def htmx_credentials(
    request: Request,
    page: int = Query(1),
    sort_by: str = Query("timestamp"),
    sort_order: str = Query("desc"),
):
    page = max(1, page)
    cache_key = f"credentials:{page}:{sort_by}:{sort_order}"
    cached = get_cached_table(cache_key)
    if cached:
        result = cached
    else:
        db = get_db()
        result = await asyncio.to_thread(
            db.get_credentials_paginated,
            page=page,
            page_size=5,
            sort_by=sort_by,
            sort_order=sort_order,
        )
        set_cached_table(cache_key, result)

    templates = get_templates()
    return templates.TemplateResponse(
        request,
        "dashboard/partials/credentials_table.html",
        {
            "dashboard_path": _dashboard_path(request),
            "items": result["credentials"],
            "pagination": result["pagination"],
            "sort_by": sort_by,
            "sort_order": sort_order,
        },
    )


# ── Attack Types ─────────────────────────────────────────────────────


@router.get("/htmx/attacks")
async def htmx_attacks(
    request: Request,
    page: int = Query(1),
    sort_by: str = Query("timestamp"),
    sort_order: str = Query("desc"),
    ip_filter: str = Query(None),
):
    page = max(1, page)
    cache_key = f"attacks:{page}:{sort_by}:{sort_order}:{ip_filter or ''}"
    cached = get_cached_table(cache_key)
    if cached:
        result = cached
    else:
        db = get_db()
        result = await asyncio.to_thread(
            db.get_attack_types_paginated,
            page=page,
            page_size=5,
            sort_by=sort_by,
            sort_order=sort_order,
            ip_filter=ip_filter,
        )
        set_cached_table(cache_key, result)

    # Transform attack data for template (join attack_types list, map id to log_id)
    items = []
    for attack in result["attacks"]:
        items.append(
            {
                "ip": attack["ip"],
                "path": attack["path"],
                "attack_type": ", ".join(attack.get("attack_types", [])),
                "user_agent": attack.get("user_agent", ""),
                "timestamp": attack.get("timestamp"),
                "log_id": attack.get("id"),
            }
        )

    templates = get_templates()
    return templates.TemplateResponse(
        request,
        "dashboard/partials/attack_types_table.html",
        {
            "dashboard_path": _dashboard_path(request),
            "items": items,
            "pagination": result["pagination"],
            "sort_by": sort_by,
            "sort_order": sort_order,
            "ip_filter": ip_filter or "",
        },
    )


# ── Attack Patterns ──────────────────────────────────────────────────


@router.get("/htmx/patterns")
async def htmx_patterns(
    request: Request,
    page: int = Query(1),
):
    page = max(1, page)
    page_size = 10

    cache_key = f"patterns:{page}"
    cached = get_cached_table(cache_key)
    if cached:
        result = cached
    else:
        db = get_db()
        # Get all attack type stats and paginate manually
        result = await asyncio.to_thread(db.get_attack_types_stats, limit=100)
        set_cached_table(cache_key, result)
    all_patterns = [
        {"pattern": item["type"], "count": item["count"]}
        for item in result.get("attack_types", [])
    ]

    total = len(all_patterns)
    total_pages = max(1, (total + page_size - 1) // page_size)
    offset = (page - 1) * page_size
    items = all_patterns[offset : offset + page_size]

    templates = get_templates()
    return templates.TemplateResponse(
        request,
        "dashboard/partials/patterns_table.html",
        {
            "dashboard_path": _dashboard_path(request),
            "items": items,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total": total,
                "total_pages": total_pages,
            },
        },
    )


# ── IP Insight (full IP page as partial) ─────────────────────────────


@router.get("/htmx/ip-insight/{ip_address:path}")
async def htmx_ip_insight(ip_address: str, request: Request):
    db = get_db()
    stats = await asyncio.to_thread(db.get_ip_stats_by_ip, ip_address)

    if not stats:
        stats = {"ip": ip_address, "total_requests": "N/A"}

    # Transform fields for template compatibility
    list_on = stats.get("list_on") or {}
    stats["blocklist_memberships"] = list(list_on.keys()) if list_on else []
    stats["reverse_dns"] = stats.get("reverse")

    is_tracked = await asyncio.to_thread(db.is_ip_tracked, ip_address)

    templates = get_templates()
    return templates.TemplateResponse(
        request,
        "dashboard/partials/ip_insight.html",
        {
            "dashboard_path": _dashboard_path(request),
            "stats": stats,
            "ip_address": ip_address,
            "is_tracked": is_tracked,
        },
    )


# ── IP Detail ────────────────────────────────────────────────────────


@router.get("/htmx/ip-detail/{ip_address:path}")
async def htmx_ip_detail(ip_address: str, request: Request):
    db = get_db()
    stats = await asyncio.to_thread(db.get_ip_stats_by_ip, ip_address)

    if not stats:
        stats = {"ip": ip_address, "total_requests": "N/A"}

    # Transform fields for template compatibility
    list_on = stats.get("list_on") or {}
    stats["blocklist_memberships"] = list(list_on.keys()) if list_on else []
    stats["reverse_dns"] = stats.get("reverse")

    is_tracked = await asyncio.to_thread(db.is_ip_tracked, ip_address)

    templates = get_templates()
    return templates.TemplateResponse(
        request,
        "dashboard/partials/ip_detail.html",
        {
            "dashboard_path": _dashboard_path(request),
            "stats": stats,
            "is_tracked": is_tracked,
        },
    )


# ── Search ───────────────────────────────────────────────────────────


@router.get("/htmx/search")
async def htmx_search(
    request: Request,
    q: str = Query(""),
    page: int = Query(1),
):
    q = q.strip()
    if not q:
        return Response(content="", media_type="text/html")

    db = get_db()
    result = await asyncio.to_thread(
        db.search_attacks_and_ips, query=q, page=max(1, page), page_size=20
    )

    templates = get_templates()
    return templates.TemplateResponse(
        request,
        "dashboard/partials/search_results.html",
        {
            "dashboard_path": _dashboard_path(request),
            "attacks": result["attacks"],
            "ips": result["ips"],
            "query": q,
            "pagination": result["pagination"],
        },
    )


# ── Protected Banlist Panel ───────────────────────────────────────────


@router.get("/htmx/banlist")
async def htmx_banlist(request: Request):
    if not verify_auth(request):
        return HTMLResponse(
            '<div class="table-container" style="text-align:center;padding:80px 20px;">'
            '<h1 style="color:#f0883e;font-size:48px;margin:20px 0 10px;">Nice try bozo</h1>'
            "<br>"
            '<img src="https://media0.giphy.com/media/v1.Y2lkPTZjMDliOTUyaHQ3dHRuN2wyOW1kZndjaHdkY2dhYzJ6d2gzMDJkNm53ZnNrdnNlZCZlcD12MV9naWZzX3NlYXJjaCZjdD1n/mOY97EXNisstZqJht9/200w.gif" alt="Diddy">'
            "</div>",
            status_code=200,
        )
    templates = get_templates()
    return templates.TemplateResponse(
        request,
        "dashboard/partials/banlist_panel.html",
        {
            "dashboard_path": _dashboard_path(request),
        },
    )


# ── Ban Management HTMX Endpoints ───────────────────────────────────


@router.get("/htmx/ban/attackers")
async def htmx_ban_attackers(
    request: Request,
    page: int = Query(1),
    page_size: int = Query(25),
):
    if not verify_auth(request):
        return HTMLResponse(
            "<p style='color:#f85149;'>Unauthorized</p>", status_code=200
        )

    db = get_db()
    result = await asyncio.to_thread(
        db.get_attackers_paginated, page=max(1, page), page_size=page_size
    )
    templates = get_templates()
    return templates.TemplateResponse(
        request,
        "dashboard/partials/ban_attackers_table.html",
        {
            "dashboard_path": _dashboard_path(request),
            "items": result["attackers"],
            "pagination": result["pagination"],
        },
    )


# ── Protected Tracked IPs Panel ──────────────────────────────────────


@router.get("/htmx/tracked-ips")
async def htmx_tracked_ips(request: Request):
    if not verify_auth(request):
        return HTMLResponse(
            '<div class="table-container" style="text-align:center;padding:80px 20px;">'
            '<h1 style="color:#f0883e;font-size:48px;margin:20px 0 10px;">Nice try bozo</h1>'
            "<br>"
            '<img src="https://media0.giphy.com/media/v1.Y2lkPTZjMDliOTUyaHQ3dHRuN2wyOW1kZndjaHdkY2dhYzJ6d2gzMDJkNm53ZnNrdnNlZCZlcD12MV9naWZzX3NlYXJjaCZjdD1n/mOY97EXNisstZqJht9/200w.gif" alt="Diddy">'
            "</div>",
            status_code=200,
        )
    templates = get_templates()
    return templates.TemplateResponse(
        request,
        "dashboard/partials/tracked_ips_panel.html",
        {
            "dashboard_path": _dashboard_path(request),
        },
    )


@router.get("/htmx/tracked-ips/list")
async def htmx_tracked_ips_list(
    request: Request,
    page: int = Query(1),
    page_size: int = Query(25),
):
    if not verify_auth(request):
        return HTMLResponse(
            "<p style='color:#f85149;'>Unauthorized</p>", status_code=200
        )

    db = get_db()
    result = await asyncio.to_thread(
        db.get_tracked_ips_paginated, page=max(1, page), page_size=page_size
    )
    templates = get_templates()
    return templates.TemplateResponse(
        request,
        "dashboard/partials/tracked_ips_table.html",
        {
            "dashboard_path": _dashboard_path(request),
            "items": result["tracked_ips"],
            "pagination": result["pagination"],
        },
    )


@router.get("/htmx/ban/overrides")
async def htmx_ban_overrides(
    request: Request,
    page: int = Query(1),
    page_size: int = Query(25),
):
    if not verify_auth(request):
        return HTMLResponse(
            "<p style='color:#f85149;'>Unauthorized</p>", status_code=200
        )

    db = get_db()
    result = await asyncio.to_thread(
        db.get_ban_overrides_paginated, page=max(1, page), page_size=page_size
    )
    templates = get_templates()
    return templates.TemplateResponse(
        request,
        "dashboard/partials/ban_overrides_table.html",
        {
            "dashboard_path": _dashboard_path(request),
            "items": result["overrides"],
            "pagination": result["pagination"],
        },
    )
