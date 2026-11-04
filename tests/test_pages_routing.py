"""Requests through the full app: YARA reply, then pages:, then the trap maze."""

import os
import sys
import tempfile
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# Route import pulls in the optional AI client, irrelevant here.
if "aiohttp" not in sys.modules:
    aiohttp_stub = types.ModuleType("aiohttp")
    aiohttp_stub.ClientSession = object
    aiohttp_stub.ClientTimeout = object
    aiohttp_stub.ClientError = Exception
    sys.modules["aiohttp"] = aiohttp_stub

from test_page_content import CASES  # noqa: E402

RESPONSES = Path(__file__).resolve().parent.parent / "responses"
CLIENT = {"X-Forwarded-For": "198.51.100.40"}


@pytest.fixture
def app_client(monkeypatch):
    """The real app with a scratch database, no delay, no AI and no imports."""
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    monkeypatch.setenv("KRAWL_DATABASE_PATH", db_path)
    from fastapi.testclient import TestClient

    import app as appmod
    from config import get_config
    from tracker import AccessTracker

    config = get_config()
    config.banlist_sources = []
    config.deception_import_pages = False
    config.delay = 0
    config.ai_enabled = False
    config.tarpit_enabled = False
    captured = []
    with (
        patch.object(config, "resolve_server_ip"),
        patch.object(
            appmod,
            "get_tasksmaster",
            return_value=SimpleNamespace(run_scheduled_tasks=lambda: None),
        ),
        patch.object(
            AccessTracker,
            "record_credential_attempt",
            lambda self, ip, path, username, password: captured.append(
                (path, username, password)
            ),
        ),
        patch("routes.honeypot.asyncio.sleep", return_value=None),
        TestClient(appmod.create_app()) as client,
    ):
        client.captured = captured
        yield client


def _request(client, method, path, query="", data=None):
    url = f"{path}?{query}" if query else path
    return client.request(method, url, headers=CLIENT, data=data)


# Paths a YARA rule answers before the page layer is reached.
YARA_FIRST = {
    "/config.json": "database_url=",  # krawl_probe_config_files -> sensitive_file
}


@pytest.mark.parametrize("method, path, status, marker", CASES)
def test_old_fixed_paths_still_answer(app_client, method, path, status, marker):
    marker = YARA_FIRST.get(path, marker)
    response = _request(app_client, method, path)

    assert response.status_code == status
    assert marker.encode() in response.content


def test_yara_reply_wins_over_a_prefix_page(app_client):
    response = _request(app_client, "GET", "/api/x", "file=../../etc/passwd")

    assert b"root:x:0:0" in response.content


def test_unknown_path_reaches_the_trap_maze(app_client):
    response = _request(app_client, "GET", "/zz/unknown")

    assert response.status_code == 200
    assert b"<a href=" in response.content


def test_head_on_a_page(app_client):
    get = _request(app_client, "GET", "/login")
    head = _request(app_client, "HEAD", "/login")

    assert head.status_code == 200
    assert head.headers["content-type"] == get.headers["content-type"]


def test_login_post_is_captured_and_gets_login_failed(app_client):
    failed = {
        item.read_bytes() for item in (RESPONSES / "pages/login_failed").iterdir()
    }

    response = _request(
        app_client, "POST", "/login", data={"username": "admin", "password": "hunter2"}
    )

    assert response.content in failed
    assert app_client.captured == [("/login", "admin", "hunter2")]


def test_post_to_a_page_is_still_captured(app_client):
    response = _request(
        app_client,
        "POST",
        "/api/contact",
        "msg=hi",
        data={"username": "a", "password": "b"},
    )

    assert b"msg=hi" in response.content
    assert response.headers["content-security-policy"] == "script-src 'none'"
    assert app_client.captured == [("/api/contact", "a", "b")]


def test_post_with_sql_injection_to_login_reaches_capture(app_client):
    _request(
        app_client,
        "POST",
        "/login",
        data={"username": "admin'--", "password": "hunter2"},
    )

    assert app_client.captured == [("/login", "admin'--", "hunter2")]


def test_robots_readers_use_the_catalogue(monkeypatch):
    import detection
    import generative_ai
    from responses import ResponseCatalog
    from tasks import analyze_ips

    catalog = ResponseCatalog.load(RESPONSES)
    monkeypatch.setattr(detection, "_catalog", catalog)
    monkeypatch.setattr(generative_ai, "_robots_disallowed_cache", None)

    assert generative_ai.load_robots_disallowed() == list(catalog.robots_disallows)
    assert analyze_ips.robots_disallows() == list(catalog.robots_disallows)
