import asyncio
from types import SimpleNamespace

import pytest
from starlette.requests import Request

import auth_store
from routes.api import AuthRequest, authenticate


@pytest.mark.parametrize(
    "expected, supplied, status",
    [
        ("ascii-example", "wrong-é", 401),
        ("example-é", "example-é", 200),
        ("example-é", "wrong", 401),
        ("ascii-example", "\ud800", 401),
    ],
)
def test_unicode_passwords_are_compared_without_server_errors(
    monkeypatch, expected, supplied, status
):
    monkeypatch.setattr(auth_store, "_sessions", {})
    monkeypatch.setattr(auth_store, "_attempts", {})
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/secret/api/auth",
            "headers": [],
            "client": ("203.0.113.7", 1234),
            "app": SimpleNamespace(
                state=SimpleNamespace(
                    config=SimpleNamespace(dashboard_password=expected),
                )
            ),
        }
    )
    response = asyncio.run(authenticate(request, AuthRequest(password=supplied)))
    assert response.status_code == status
    if status == 200:
        assert "krawl_auth=" in response.headers["set-cookie"]
        assert not auth_store.get_attempts("203.0.113.7")
    else:
        assert auth_store.get_attempts("203.0.113.7")["attempts"] == 1
