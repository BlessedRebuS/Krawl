#!/usr/bin/env python3

"""
Middleware for checking if client IP is banned.
Returns 429 Too Many Requests with a Retry-After header for banned IPs.
"""

import asyncio

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from dependencies import get_client_ip
from ip_utils import is_local_or_private_ip


class BanCheckMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip ban check for dashboard routes
        config = request.app.state.config
        dashboard_prefix = "/" + config.dashboard_secret_path.lstrip("/")
        if request.url.path.startswith(dashboard_prefix):
            return await call_next(request)

        client_ip = get_client_ip(request)

        # Private/local/reserved IPs (e.g. k8s health-check sources) are never
        # banned, so skip the ban check entirely for them.
        if is_local_or_private_ip(client_ip):
            return await call_next(request)

        tracker = request.app.state.tracker

        from logger import get_app_logger

        get_app_logger().debug(
            f"[BanCheck] Checking ban for {client_ip} - {request.url.path}"
        )
        ban_info = await asyncio.to_thread(tracker.get_ban_info, client_ip)
        if ban_info["is_banned"]:
            from logger import get_access_logger

            get_access_logger().info(
                f"[BANNED] [{request.method}] {client_ip} - {request.url.path}"
            )
            request.state.banned = True
            retry_after = int(ban_info["remaining_ban_seconds"])
            return Response(
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )

        response = await call_next(request)
        return response
