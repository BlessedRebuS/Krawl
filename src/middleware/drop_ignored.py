#!/usr/bin/env python3

"""Answer ignored IPs at the edge, before anything allocates."""

from dependencies import get_client_ip_from_scope
from ip_utils import is_ignored_ip
from logger import get_access_logger

# Sent verbatim to every dropped request. Built once: the whole point is that a
# dropped request allocates as close to nothing as ASGI allows.
_DROP_START = {
    "type": "http.response.start",
    "status": 204,
    "headers": [(b"content-length", b"0")],
}
_DROP_BODY = {"type": "http.response.body", "body": b""}


class DropIgnoredMiddleware:
    """Reply to ignored IPs from the ASGI scope alone.

    Pure ASGI, not BaseHTTPMiddleware, and deliberately the outermost layer.
    Everything below it costs memory per request: BaseHTTPMiddleware builds a
    Request and an anyio task group per hop, the deception middleware reads and
    decodes the body, the honeypot route generates a page, and the tracking
    dependency builds a 16 KiB raw-request string. For an address we have
    already decided to ignore, every one of those allocations is thrown away —
    and under an IPv6 proxy flood that is what fills the pod until the OOM
    killer takes it.

    So the request is answered from the scope: headers for the client IP, then
    a canned 204. The body is never read, which also means a large upload from
    an ignored address costs nothing but the socket.

    Dashboard traffic is exempt. Without that, turning on ipv6.ignore would
    lock an operator out of their own dashboard over IPv6, and the k8s health
    probe (which lives under the dashboard prefix) would stop being served.

    204 rather than 404 so that anything treating 2xx as healthy — an uptime
    check hitting the honeypot from a private, and therefore ignored, address —
    keeps passing.
    """

    def __init__(self, app, dashboard_prefix: str):
        self.app = app
        self.dashboard_prefix = dashboard_prefix

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        if path.startswith(self.dashboard_prefix):
            return await self.app(scope, receive, send)

        client_ip = get_client_ip_from_scope(scope)
        if not is_ignored_ip(client_ip):
            return await self.app(scope, receive, send)

        # Still logged to stdout: dropping is about not persisting or
        # allocating, not about going blind.
        get_access_logger().info(
            f"[IGNORED] [{scope.get('method', '?')}] {client_ip} - {path}"
        )
        await send(_DROP_START)
        await send(_DROP_BODY)
