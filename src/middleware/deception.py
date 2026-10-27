#!/usr/bin/env python3

"""
Middleware that answers detected attacks with a fake response from the catalogue
(responses/manifest.yaml). Short-circuits the request when a response is chosen.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from dependencies import build_raw_request, get_client_ip, read_body_capped
from detection import get_response_catalog
from logger import get_access_logger, get_app_logger


class DeceptionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip deception detection for dashboard routes
        config = request.app.state.config
        dashboard_prefix = "/" + config.dashboard_secret_path.lstrip("/")
        if path == dashboard_prefix or path.startswith(dashboard_prefix + "/"):
            return await call_next(request)

        get_app_logger().debug(f"[Deception] Processing {request.method} {path}")
        query = request.url.query or ""
        method = request.method

        # Read body for POST requests, bounded — see read_body_capped.
        body_bytes = b""
        body = ""
        if method == "POST":
            body_bytes = await read_body_capped(request)
            body = body_bytes.decode("utf-8", errors="replace")

        tracker = request.app.state.tracker
        detection_findings = tracker.detector.scan_request(
            path=path,
            query=query,
            body=body,
            user_agent=request.headers.get("User-Agent", ""),
            method=method,
            headers=request.headers.items(),
        )
        # The honeypot dependency reuses these instead of scanning again.
        request.state.detection_findings = detection_findings
        reply = get_response_catalog().select(detection_findings, method, path, query)

        if reply:
            client_ip = get_client_ip(request)
            user_agent = request.headers.get("User-Agent", "")
            access_logger = get_access_logger()

            access_logger.warning(
                f"[{reply.finding.attack_type.upper()} DETECTED] {client_ip} - {path[:100]} - Method: {method}"
            )

            # Record access (run in thread to avoid blocking event loop)
            import asyncio

            file_payloads = []
            if body_bytes:
                from tlsh_utils import extract_file_payloads_from_body

                file_payloads = extract_file_payloads_from_body(
                    body_bytes,
                    request.headers.get("Content-Type", ""),
                    compute_tlsh=config.tlsh_enabled,
                    filename_hint=path.rstrip("/").rsplit("/", 1)[-1],
                )
            await asyncio.to_thread(
                tracker.record_access,
                ip=client_ip,
                path=path,
                user_agent=user_agent,
                body=body,
                query=query,
                method=method,
                raw_request=build_raw_request(request, body),
                file_payloads=file_payloads,
                target_host=request.headers.get("Host", ""),
                detection_findings=detection_findings,
            )

            return Response(
                content=reply.body,
                status_code=reply.status,
                media_type=reply.content_type,
                headers=dict(reply.headers),
            )

        response = await call_next(request)
        return response
