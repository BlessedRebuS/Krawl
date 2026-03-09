#!/usr/bin/env python3

"""
Middleware for checking if client IP is banned.
Resets the connection for banned IPs instead of sending a response.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from dependencies import get_client_ip


class BanCheckMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip ban check for dashboard routes
        config = request.app.state.config
        dashboard_prefix = "/" + config.dashboard_secret_path.lstrip("/")
        if request.url.path.startswith(dashboard_prefix):
            return await call_next(request)

        client_ip = get_client_ip(request)
        tracker = request.app.state.tracker

        if tracker.is_banned_ip(client_ip):
            from logger import get_access_logger

            get_access_logger().info(
                f"[BANNED] [{request.method}] {client_ip} - {request.url.path}"
            )
            transport = request.scope.get("transport")
            if transport:
                transport.close()
            return Response(status_code=500)

        response = await call_next(request)
        return response
