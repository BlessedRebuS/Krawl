#!/usr/bin/env python3

"""
Per-request memory must be bounded regardless of what the client sends.

Two defences, both added after pods were OOM-killed (exit 137) under a flood:

1. read_body_capped: `request.body()` concatenates every chunk with no
   ceiling. content-length does not bound it — a `Transfer-Encoding: chunked`
   request declares none, so the old content-length guard returned False and a
   single request could buffer gigabytes.
2. DropIgnoredMiddleware: an ignored address is answered from the ASGI scope,
   so its body is never read and no downstream layer allocates for it.

Usage: python tests/test_request_memory_bounds.py
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from starlette.requests import Request

from dependencies import MAX_BODY_BYTES, body_too_large, read_body_capped

V6 = "2a13:f41:90a8:10ba::dead"
V4 = "203.0.113.7"


def _request(headers, chunks):
    """A Request whose stream yields `chunks`, with no content-length unless given."""
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/wp-login.php",
        "query_string": b"",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": ("203.0.113.7", 1234),
    }
    queue = list(chunks)

    async def receive():
        if queue:
            return {
                "type": "http.request",
                "body": queue.pop(0),
                "more_body": bool(queue),
            }
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive)


def test_chunked_body_is_capped():
    """The hole: no content-length, so the declared-size guard never fires."""
    huge = [b"A" * 65536] * 200  # 12.8 MB across 200 chunks

    req = _request({"transfer-encoding": "chunked"}, huge)
    assert body_too_large(req) is False, (
        "guard cannot see a chunked body — that is the point"
    )

    body = asyncio.run(read_body_capped(req))
    assert body == b"", f"oversized body must yield nothing, got {len(body)} bytes"

    # Cached, so the route does not re-read the stream and get a different answer.
    assert asyncio.run(read_body_capped(req)) == b""
    print(f"OK: 12.8 MB chunked body held 0 bytes (cap {MAX_BODY_BYTES})")


def test_body_under_cap_is_preserved():
    """The cap must not break normal POSTs — attack detection reads this."""
    payload = b"log=admin&pwd=hunter2"
    req = _request({"content-length": str(len(payload))}, [payload])
    assert asyncio.run(read_body_capped(req)) == payload

    # Exactly at the cap is still fine; one byte over is not.
    at_cap = b"B" * MAX_BODY_BYTES
    assert len(asyncio.run(read_body_capped(_request({}, [at_cap])))) == MAX_BODY_BYTES
    over = b"B" * (MAX_BODY_BYTES + 1)
    assert asyncio.run(read_body_capped(_request({}, [over]))) == b""
    print("OK: bodies at or under the cap are preserved intact")


def test_ignored_ip_never_reads_the_body():
    os.environ["KRAWL_DATABASE_PATH"] = tempfile.mkstemp(suffix=".db")[1]
    os.environ["KRAWL_IPV6_IGNORE"] = "true"
    from fastapi.testclient import TestClient

    import app as appmod
    from database import get_database
    from models import AccessLog

    application = appmod.create_app()
    assert application.user_middleware[0].cls.__name__ == "DropIgnoredMiddleware", (
        "the drop layer must be outermost or the layers below still allocate"
    )

    with TestClient(application) as client:

        def big():
            for _ in range(200):
                yield b"A" * 65536

        r = client.post("/wp-login.php", content=big(), headers={"X-Forwarded-For": V6})
        assert r.status_code == 204 and r.content == b"", (
            r.status_code,
            len(r.content),
        )

        # A public address still gets the honeypot, and its oversized body is
        # dropped rather than stored.
        r = client.post("/wp-login.php", content=big(), headers={"X-Forwarded-For": V4})
        assert r.status_code == 200

        session = get_database().session
        assert session.query(AccessLog).filter(AccessLog.ip.like("%:%")).count() == 0
        for row in session.query(AccessLog).filter(AccessLog.ip == V4).all():
            raw = row.raw_request or ""
            assert "AAAA" not in raw, "oversized body leaked into raw_request"
            assert len(raw) <= 16 * 1024, len(raw)

    os.unlink(os.environ["KRAWL_DATABASE_PATH"])
    print("OK: ignored IP answered with 204 and no body read; public IP body capped")


if __name__ == "__main__":
    test_chunked_body_is_capped()
    test_body_under_cap_is_preserved()
    test_ignored_ip_never_reads_the_body()
