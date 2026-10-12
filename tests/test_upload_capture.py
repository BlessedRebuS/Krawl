#!/usr/bin/env python3

"""Ordinary file uploads are evidence even without an attack signature."""

import asyncio
import hashlib
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# Route import pulls in the optional AI client, which is irrelevant here and is
# not installed in the lightweight unit-test environment.
if "aiohttp" not in sys.modules:
    aiohttp_stub = types.ModuleType("aiohttp")
    aiohttp_stub.ClientSession = object
    aiohttp_stub.ClientTimeout = object
    aiohttp_stub.ClientError = Exception
    sys.modules["aiohttp"] = aiohttp_stub

from starlette.requests import Request

from config import get_config
from dependencies import MAX_RAW_REQUEST
from routes.honeypot import _track_honeypot_request, router


class _Tracker:
    def __init__(self):
        self.recorded = []

    def detect_attack_type(self, _value):
        return []

    def is_honeypot_path(self, _path):
        return False

    def record_access(self, **kwargs):
        self.recorded.append(kwargs)


def _multipart_request(method: str, content: bytes, tracker: _Tracker) -> Request:
    boundary = "upload-boundary"
    body = (
        (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="document"; filename="report.bin"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        + content
        + f"\r\n--{boundary}--\r\n".encode()
    )
    headers = {
        "host": "uploads.example:8443",
        "content-type": f"multipart/form-data; boundary={boundary}",
        "content-length": str(len(body)),
        "x-forwarded-for": "203.0.113.44",
    }
    scope = {
        "type": "http",
        "method": method,
        "path": "/ordinary-upload",
        "query_string": b"",
        "headers": [(key.encode(), value.encode()) for key, value in headers.items()],
        "client": ("203.0.113.44", 1234),
        "app": SimpleNamespace(state=SimpleNamespace(tracker=tracker)),
    }
    pending = [body]

    async def receive():
        return {
            "type": "http.request",
            "body": pending.pop(0) if pending else b"",
            "more_body": False,
        }

    return Request(scope, receive)


def test_unmatched_uploads_are_captured_with_tlsh_disabled():
    tracker = _Tracker()
    # Larger than the forensic raw-request cap. The complete body remains below
    # MAX_BODY_BYTES and must be extracted from request bytes before truncation.
    content = bytes(range(256)) * 80
    config = get_config()

    async def inline_to_thread(func, *args, **kwargs):
        return func(*args, **kwargs)

    with (
        patch.object(config, "tlsh_enabled", False),
        patch("routes.honeypot.asyncio.to_thread", side_effect=inline_to_thread),
    ):
        for method in ("POST", "PUT"):
            asyncio.run(
                _track_honeypot_request(_multipart_request(method, content, tracker))
            )

    assert len(tracker.recorded) == 2
    for method, call in zip(("POST", "PUT"), tracker.recorded, strict=True):
        assert call["method"] == method
        assert call["target_host"] == "uploads.example:8443"
        assert len(call["raw_request"]) == MAX_RAW_REQUEST
        assert len(call["file_payloads"]) == 1
        payload = call["file_payloads"][0]
        assert payload["filename"] == "report.bin"
        assert payload["size"] == len(content)
        assert payload["sha256"] == hashlib.sha256(content).hexdigest()
        assert payload["tlsh_hash"] is None

    # APIRouter dependencies only execute after a route matches, so PUT needs a
    # catch-all route just as POST does.
    assert any(
        route.path == "/{path:path}" and "PUT" in route.methods
        for route in router.routes
    )


if __name__ == "__main__":
    test_unmatched_uploads_are_captured_with_tlsh_disabled()
    print("OK: unmatched POST/PUT uploads captured with TLSH disabled")
