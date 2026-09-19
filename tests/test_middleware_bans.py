import asyncio
from types import SimpleNamespace

import pytest
from starlette.requests import Request
from starlette.responses import Response

import ban_cache
import banlist_sync
from middleware.ban_check import BanCheckMiddleware
from middleware.drop_ignored import DropIgnoredMiddleware


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/probe", 429),
        ("/secret-lookalike", 429),
        ("/secret", 200),
        ("/secret/api/stats", 200),
    ],
)
def test_global_ban_and_dashboard_path_boundary(monkeypatch, path, expected):
    monkeypatch.setattr(ban_cache, "_ready", True)
    monkeypatch.setattr(ban_cache, "_banned", set())
    monkeypatch.setattr(banlist_sync, "_global_banlist", frozenset({"8.8.8.8"}))
    state = SimpleNamespace(
        config=SimpleNamespace(
            dashboard_secret_path="secret",  # noqa: S106 -- test-only route prefix
            banlist_export_path="",
            banlist_sources=["test"],
        ),
        tracker=SimpleNamespace(),
    )
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "headers": [],
            "query_string": b"",
            "client": ("8.8.8.8", 1234),
            "app": SimpleNamespace(state=state),
        }
    )

    async def next_handler(request):
        return Response(status_code=200)

    response = asyncio.run(BanCheckMiddleware(None).dispatch(request, next_handler))
    assert response.status_code == expected
    if expected == 429:
        assert response.headers["retry-after"] == "3600"


def test_ignored_ip_cannot_bypass_drop_with_prefix_lookalike():
    responses = []

    async def downstream(*args):
        pytest.fail("lookalike path bypassed the ignored-IP guard")

    async def receive():
        pytest.fail("ignored body was read")

    async def send(message):
        responses.append(message)

    app = DropIgnoredMiddleware(downstream, "/secret")
    asyncio.run(
        app(
            {
                "type": "http",
                "path": "/secret-lookalike",
                "method": "POST",
                "client": ("127.0.0.1", 1234),
                "headers": [],
            },
            receive,
            send,
        )
    )
    assert responses[0]["status"] == 204
