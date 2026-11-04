"""
Replay the fake attack corpus through the real request path.

Each request goes through DeceptionMiddleware and the honeypot dependency with
the bundled YARA rules, and the test asserts on what reaches the tracker, so a
rule that compiles but never fires on real traffic shows up here.
"""

import asyncio
import sys
import urllib.parse
from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.requests import Request
from starlette.responses import Response

from detection import DetectionCoordinator, YaraDetectionEngine

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from fake_attacks import ATTACKS, BENIGN, FakeRequest  # noqa: E402

RULES = Path(__file__).resolve().parent.parent / "rules"


class RecordingTracker:
    """Tracker double that keeps what record_access receives."""

    def __init__(self, detector):
        self.detector = detector
        self.recorded = []

    def is_honeypot_path(self, path):
        return False

    def record_access(self, **kwargs):
        self.recorded.append(kwargs)


@pytest.fixture(scope="module")
def detector():
    return DetectionCoordinator(YaraDetectionEngine(RULES))


def _replay(item: FakeRequest, detector):
    """Return the request's findings and the tracker that saw it."""
    from middleware.deception import DeceptionMiddleware
    from routes.honeypot import _track_honeypot_request

    tracker = RecordingTracker(detector)
    state = SimpleNamespace(
        config=SimpleNamespace(
            dashboard_secret_path="secret",  # noqa: S106 -- test-only route prefix
            tlsh_enabled=False,
        ),
        tracker=tracker,
    )
    headers = {"user-agent": item.user_agent, "host": "honeypot.test"}
    headers.update({key.lower(): value for key, value in item.headers.items()})
    body = item.body.encode()
    if body:
        headers["content-length"] = str(len(body))
    # Mirror an ASGI server: scope["path"] is percent-decoded, the query is raw.
    query = urllib.parse.quote(item.query, safe="=&+%")
    scope = {
        "type": "http",
        "method": item.method,
        "path": urllib.parse.unquote(item.path),
        "raw_path": item.path.encode(),
        "query_string": query.encode(),
        "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
        "client": ("198.51.100.20", 40000),
        "app": SimpleNamespace(state=state),
    }
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def downstream(request):
        await _track_honeypot_request(request)
        return Response(status_code=200)

    request = Request(scope, receive)
    asyncio.run(DeceptionMiddleware(None).dispatch(request, downstream))
    return request.state.detection_findings, tracker


@pytest.mark.parametrize("item", ATTACKS, ids=lambda item: item.name)
def test_fake_attack_is_detected_with_expected_type(item, detector):
    findings, tracker = _replay(item, detector)

    matching = [finding for finding in findings if finding.attack_type == item.expect]
    assert matching, f"{item.name}: got {[f.attack_type for f in findings]}"
    # Attacks are persisted with their findings; a suspicious user agent alone
    # is logged later by the route handler, not by the honeypot dependency.
    if any(finding.classification == "attack" for finding in matching):
        assert tracker.recorded, f"{item.name} was not recorded"
        assert len(tracker.recorded) == 1, f"{item.name} was recorded twice"
        assert tracker.recorded[0]["detection_findings"] == findings


@pytest.mark.parametrize("item", BENIGN, ids=lambda item: item.name)
def test_benign_request_has_no_findings(item, detector):
    findings, tracker = _replay(item, detector)

    assert [finding.attack_type for finding in findings] == []
    assert tracker.recorded == []


def test_every_bundled_attack_type_has_a_fake_attack(detector):
    import yara

    rule_types = set()

    def collect(rule):
        rule_types.add(rule["meta"]["attack_type"])
        return yara.CALLBACK_CONTINUE

    detector.yara.rules.match(
        data=b"",
        callback=collect,
        which_callbacks=yara.CALLBACK_ALL,
        externals={"scan_target": "", "http_method": "", "header_name": ""},
    )

    assert rule_types - {item.expect for item in ATTACKS} == set()


class CatchAllTracker(RecordingTracker):
    """Adds what trap_page itself calls on the tracker."""

    def record_access(self, **kwargs):
        super().record_access(**kwargs)
        return 1

    def increment_page_visit(self, ip):
        return 1

    def is_suspicious_user_agent(self, user_agent):
        return False

    def detect_attack_type(self, data, exclude=None):
        return []

    def __getattr__(self, name):
        # trap_page renders a page afterwards; nothing there affects recording.
        return lambda *args, **kwargs: None


@pytest.mark.parametrize(
    "item",
    [
        item
        for item in ATTACKS
        if item.name in {"cloud metadata", "shellshock user agent"}
    ],
    ids=lambda item: item.name,
)
def test_catch_all_route_records_attack_once(item, detector):
    from config import get_config
    from routes.honeypot import _track_honeypot_request, trap_page

    tracker = CatchAllTracker(detector)
    state = SimpleNamespace(config=get_config(), tracker=tracker)
    scope = {
        "type": "http",
        "method": "GET",
        "path": item.path,
        "query_string": urllib.parse.quote(item.query, safe="=&+%").encode(),
        "headers": [(b"user-agent", item.user_agent.encode())],
        "client": ("198.51.100.20", 40000),
        "app": SimpleNamespace(state=state),
    }
    request = Request(scope)

    async def run():
        await _track_honeypot_request(request)
        try:
            await trap_page(request, item.path.lstrip("/"))
        except Exception:  # noqa: S110 -- page rendering is out of scope here
            pass

    asyncio.run(run())

    assert len(tracker.recorded) == 1


def _rule_attack_types(detector):
    import yara

    found = {}

    def collect(rule):
        found[rule["rule"]] = rule["meta"]["attack_type"]
        return yara.CALLBACK_CONTINUE

    detector.yara.rules.match(
        data=b"",
        callback=collect,
        which_callbacks=yara.CALLBACK_ALL,
        externals={"scan_target": "", "http_method": "", "header_name": ""},
    )
    return found


def test_every_attack_names_the_rule_that_must_fire(detector):
    rules = _rule_attack_types(detector)

    for item in ATTACKS:
        assert item.rule in rules, f"{item.name}: unknown rule {item.rule!r}"
        assert rules[item.rule] == item.expect, f"{item.name}: type/rule mismatch"


def test_every_bundled_rule_has_a_fake_attack(detector):
    assert set(_rule_attack_types(detector)) - {item.rule for item in ATTACKS} == set()


@pytest.mark.parametrize("item", ATTACKS, ids=lambda item: item.name)
def test_fake_attack_fires_its_named_rule(item, detector):
    raw = list(
        detector.iter_findings(
            path=urllib.parse.unquote(item.path),
            query=item.query,
            body=item.body,
            user_agent=item.user_agent,
            method=item.method,
            headers={
                "host": "honeypot.test",
                **{k.lower(): v for k, v in item.headers.items()},
            }.items(),
        )
    )

    assert item.rule in {finding.rule_name for finding in raw}, (
        f"{item.name}: got {sorted({f.rule_name for f in raw})}"
    )


def test_replay_selects_by_attack_type_or_rule_name():
    from fake_attacks import select_corpus

    by_type = select_corpus("log4shell")
    by_rule = select_corpus("krawl_log4shell")

    assert by_type and by_type == by_rule
    assert select_corpus("no_such_thing") == []
    assert select_corpus(None) == ATTACKS
    assert select_corpus(None, benign=True) == ATTACKS + BENIGN
