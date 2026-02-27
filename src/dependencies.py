#!/usr/bin/env python3

"""
FastAPI dependency injection providers.
Replaces Handler class variables with proper DI.
"""

import os
from datetime import datetime

from fastapi import Request
from fastapi.templating import Jinja2Templates

from config import Config
from tracker import AccessTracker
from database import DatabaseManager, get_database
from logger import get_app_logger, get_access_logger, get_credential_logger

# Shared Jinja2 templates instance
_templates = None


def get_templates() -> Jinja2Templates:
    """Get shared Jinja2Templates instance with custom filters."""
    global _templates
    if _templates is None:
        templates_dir = os.path.join(os.path.dirname(__file__), "templates", "jinja2")
        _templates = Jinja2Templates(directory=templates_dir)
        _templates.env.filters["format_ts"] = _format_ts
    return _templates


def _format_ts(value):
    """Custom Jinja2 filter for formatting ISO timestamps."""
    if not value:
        return "N/A"
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except (ValueError, TypeError):
            return value
    if value.date() == datetime.now().date():
        return value.strftime("%H:%M:%S")
    return value.strftime("%m/%d/%Y %H:%M:%S")


def get_tracker(request: Request) -> AccessTracker:
    return request.app.state.tracker


def get_app_config(request: Request) -> Config:
    return request.app.state.config


def get_db() -> DatabaseManager:
    return get_database()


def get_client_ip(request: Request) -> str:
    """Extract client IP address from request, checking proxy headers first."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    if request.client:
        return request.client.host

    return "0.0.0.0"


def build_raw_request(request: Request, body: str = "") -> str:
    """Build raw HTTP request string for forensic analysis."""
    try:
        raw = f"{request.method} {request.url.path}"
        if request.url.query:
            raw += f"?{request.url.query}"
        raw += f" HTTP/1.1\r\n"

        for header, value in request.headers.items():
            raw += f"{header}: {value}\r\n"

        raw += "\r\n"

        if body:
            raw += body

        return raw
    except Exception as e:
        return f"{request.method} {request.url.path} (error building full request: {str(e)})"
