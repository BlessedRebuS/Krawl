#!/usr/bin/env python3

"""
Middleware for deception response detection (path traversal, XXE, command injection).
Short-circuits the request if a deception response is triggered.
"""

import asyncio
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from deception_responses import detect_and_respond_deception
from dependencies import get_client_ip, build_raw_request
from logger import get_app_logger, get_access_logger


class DeceptionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip deception detection for dashboard routes
        config = request.app.state.config
        dashboard_prefix = "/" + config.dashboard_secret_path.lstrip("/")
        if path.startswith(dashboard_prefix):
            return await call_next(request)

        query = request.url.query or ""
        method = request.method

        # Read body for POST requests
        body = ""
        if method == "POST":
            body_bytes = await request.body()
            body = body_bytes.decode("utf-8", errors="replace")

        result = detect_and_respond_deception(path, query, body, method)

        if result:
            response_body, content_type, status_code = result
            client_ip = get_client_ip(request)
            user_agent = request.headers.get("User-Agent", "")
            app_logger = get_app_logger()
            access_logger = get_access_logger()

            # Determine attack type for logging
            full_input = f"{path} {query} {body}".lower()
            attack_type_log = "UNKNOWN"

            if (
                "passwd" in path.lower()
                or "shadow" in path.lower()
                or ".." in path
                or ".." in query
            ):
                attack_type_log = "PATH_TRAVERSAL"
            elif body and ("<!DOCTYPE" in body or "<!ENTITY" in body):
                attack_type_log = "XXE_INJECTION"
            elif any(
                pattern in full_input
                for pattern in [
                    "cmd=",
                    "exec=",
                    "command=",
                    "execute=",
                    "system=",
                    ";",
                    "|",
                    "&&",
                    "whoami",
                    "id",
                    "uname",
                    "cat",
                    "ls",
                    "pwd",
                ]
            ):
                attack_type_log = "COMMAND_INJECTION"

            access_logger.warning(
                f"[{attack_type_log} DETECTED] {client_ip} - {path[:100]} - Method: {method}"
            )

            # Record access
            tracker = request.app.state.tracker
            tracker.record_access(
                ip=client_ip,
                path=path,
                user_agent=user_agent,
                body=body,
                method=method,
                raw_request=build_raw_request(request, body),
            )

            return Response(
                content=response_body,
                status_code=status_code,
                media_type=content_type,
            )

        response = await call_next(request)
        return response
