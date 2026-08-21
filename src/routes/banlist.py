import asyncio

from fastapi import Request, Response
from fastapi.responses import PlainTextResponse

from ip_utils import is_valid_public_ip


async def public_banlist_handler(request: Request):
    """Public banlist endpoint.

    Supports ?categories= and ?fwtype= parameters (same as the
    main /api/export-ips endpoint). Does NOT support merge_banlists
    to avoid recursive fetching when this URL is used as a source.
    """
    config = request.app.state.config
    export_path = config.banlist_export_path

    if not export_path:
        return PlainTextResponse(content="", status_code=404)

    db = request.app.state.tracker.db
    if not db:
        return PlainTextResponse(content="", status_code=503)

    categories_str = request.query_params.get("categories")
    fwtype_str = request.query_params.get("fwtype", "raw")

    valid = {"attacker", "bad_crawler", "regular_user", "good_crawler", "timed_out"}
    if categories_str:
        cat_list = [c.strip() for c in categories_str.split(",") if c.strip() in valid]
    else:
        cat_list = ["attacker", "bad_crawler", "regular_user", "good_crawler"]

    server_ip = config.get_server_ip()

    ip_set: set[str] = set()

    real_cats = [c for c in cat_list if c != "timed_out"]
    if real_cats:
        ips = await asyncio.to_thread(db.ip_stats.get_ips_for_export, real_cats)
        ip_set.update(ips)

    if "timed_out" in cat_list:
        timedout = await asyncio.to_thread(
            db.ip_stats.get_timedout_ips, config.ban_duration_seconds
        )
        ip_set.update(timedout)

    from firewall import format_banlist

    public_ips = [ip for ip in ip_set if is_valid_public_ip(ip, server_ip)]
    try:
        content = format_banlist(fwtype_str, public_ips)
    except ValueError as e:
        return PlainTextResponse(content=str(e), status_code=400)

    cat_label = "_".join(sorted(cat_list))
    filename = f"{fwtype_str}_{cat_label}_banlist.txt"

    return Response(
        content=content,
        status_code=200,
        media_type="text/plain",
        headers={
            "Content-Disposition": f'inline; filename="{filename}"',
            "Content-Length": str(len(content.encode("utf-8"))),
        },
    )
