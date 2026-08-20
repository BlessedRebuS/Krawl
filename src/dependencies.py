#!/usr/bin/env python3

"""
FastAPI dependency injection providers.
Replaces Handler class variables with proper DI.
"""

import os
from datetime import datetime

from fastapi import Request
from fastapi.templating import Jinja2Templates
from jinja2 import select_autoescape

from database import DatabaseManager, get_database

# Shared Jinja2 templates instance
_templates = None


def get_templates() -> Jinja2Templates:
    """Get shared Jinja2Templates instance with custom filters and secure configuration."""
    global _templates
    if _templates is None:
        templates_dir = os.path.join(os.path.dirname(__file__), "templates", "jinja2")
        _templates = Jinja2Templates(directory=templates_dir)
        # Enable autoescape to prevent XSS vulnerabilities
        _templates.env.autoescape = select_autoescape(
            enabled_extensions=("html", "xml", "jinja2"),
            default_for_string=True,
            default=True,
        )
        _templates.env.filters["format_ts"] = _format_ts
        _templates.env.filters["format_size"] = _format_size
    return _templates


def _format_ts(value, time_only=False):
    """Custom Jinja2 filter for formatting ISO timestamps."""
    if not value:
        return "N/A"
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except (ValueError, TypeError):
            return value
    if time_only:
        return value.strftime("%H:%M:%S")
    if value.date() == datetime.now().date():
        return value.strftime("%H:%M:%S")
    return value.strftime("%d/%m/%Y %H:%M:%S")


def _format_size(value):
    """Format byte count as B / KB / MB using 1024-based thresholds."""
    if not value:
        return "0 B"
    value = int(value)
    if value < 1024:
        return f"{value} B"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f} KB"
    return f"{value / (1024 * 1024):.1f} MB"


def get_db() -> DatabaseManager:
    return get_database()


def get_client_ip(request: Request) -> str:
    """Extract client IP address from request, checking proxy headers in order from wordlists."""
    from wordlists import get_wordlists

    for header in get_wordlists().proxy_headers:
        value = request.headers.get(header)
        if value:
            # X-Forwarded-For can contain multiple IPs, take the first
            return value.split(",")[0].strip()

    if request.client:
        return request.client.host

    return "0.0.0.0"  # noqa: S104 — sentinel for unknown client, not a socket bind


# Keep the request line, headers and start of body; never a whole upload.
MAX_RAW_REQUEST = 16 * 1024

# Starlette caches request.body() for the middleware and the route to share;
# refusing early on content-length keeps that shared copy small.
MAX_BODY_BYTES = 64 * 1024


def body_too_large(request: Request) -> bool:
    """True when the declared body exceeds what we are willing to buffer."""
    try:
        return int(request.headers.get("content-length") or 0) > MAX_BODY_BYTES
    except ValueError:
        return False


def build_raw_request(request: Request, body: str = "") -> str:
    """Build raw HTTP request string for forensic analysis (capped)."""
    try:
        raw = f"{request.method} {request.url.path}"
        if request.url.query:
            raw += f"?{request.url.query}"
        raw += " HTTP/1.1\r\n"

        for header, value in request.headers.items():
            raw += f"{header}: {value}\r\n"

        raw += "\r\n"

        if body:
            raw += body

        return raw[:MAX_RAW_REQUEST]
    except Exception as e:
        return f"{request.method} {request.url.path} (error building full request: {str(e)})"
