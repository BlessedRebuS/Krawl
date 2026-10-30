"""The Attacks query filters by period window, rule and severity band."""

import sys
import types
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

if "aiohttp" not in sys.modules:
    aiohttp_stub = types.ModuleType("aiohttp")
    aiohttp_stub.ClientSession = object
    aiohttp_stub.ClientTimeout = object
    aiohttp_stub.ClientError = Exception
    sys.modules["aiohttp"] = aiohttp_stub

import detection  # noqa: E402
from database import get_database, initialize_database  # noqa: E402
from models import AccessLog, AttackDetection  # noqa: E402
from period import resolve_period  # noqa: E402

NOW = datetime(2026, 10, 27, 12, 0, 0)

RULES = {
    "login_attempt": [{"rule": "r_login", "severity": 4}],
    "path_traversal": [
        {"rule": "r_pt1", "severity": 7},
        {"rule": "r_pt2", "severity": 8},
    ],
}


@pytest.fixture
def stored(tmp_path, monkeypatch):
    stub = SimpleNamespace(
        yara=SimpleNamespace(rule_details=RULES),
        attack_type_severity=lambda t: max(
            (r["severity"] for r in RULES.get(t, ())), default=0
        ),
    )
    monkeypatch.setattr(detection, "_coordinator", stub)
    initialize_database(str(tmp_path / "x.db"))
    db = get_database()
    s = db.session
    rows = [
        ("/a", "login_attempt", "r_login", timedelta(hours=1)),
        ("/d", "login_attempt", None, timedelta(hours=2)),
        ("/e", "path_traversal", None, timedelta(hours=3)),
        ("/c", "cve_x", None, timedelta(hours=5)),
        ("/b", "path_traversal", "r_pt1", timedelta(hours=30)),
        ("/f", "cve_x", None, timedelta(days=10)),
    ]
    for path, attack_type, rule, age in rows:
        log = AccessLog(
            ip="203.0.113.1",
            path=path,
            method="GET",
            is_suspicious=True,
            timestamp=NOW - age,
        )
        s.add(log)
        s.flush()
        s.add(
            AttackDetection(
                access_log_id=log.id, attack_type=attack_type, rule_name=rule
            )
        )
    s.commit()
    db.close_session()
    return db


def _query(db, **kw):
    result = db.analytics.get_attack_types_paginated(page_size=10, **kw)
    return [a["path"] for a in result["attacks"]], result["pagination"]["total"]


def _window(**kw):
    p = resolve_period(now=NOW, **{"days": 7, **kw})
    return {"since": p.since, "until": p.until}


def test_period_excludes_rows_outside_window(stored):
    assert _query(stored, **_window()) == (["/a", "/d", "/e", "/c", "/b"], 5)


def test_slot_keeps_only_that_bucket(stored):
    w = _window(days=1, slot="2026-10-27T11")
    assert _query(stored, **w) == (["/a"], 1)


def test_rule_filter_credits_legacy_rows_to_sole_rule_only(stored):
    assert _query(stored, rule_filter="r_login") == (["/a", "/d"], 2)
    assert _query(stored, rule_filter="r_pt1") == (["/b"], 1)


def test_severity_filter_by_band(stored):
    assert _query(stored, severity_filter=["high"], **_window()) == (["/e", "/b"], 2)
    assert _query(stored, severity_filter=["medium", "high"], **_window())[1] == 4


def test_severity_filter_low_includes_unknown_types(stored):
    assert _query(stored, severity_filter=["low"]) == (["/c", "/f"], 2)


def test_empty_range_returns_empty_pages(stored):
    assert _query(stored, since=NOW + timedelta(days=1)) == ([], 0)


def test_facets_count_by_band_and_rule(stored):
    facets = stored.analytics.get_attack_facets(**_window())
    assert facets["severities"] == {"critical": 0, "high": 2, "medium": 2, "low": 1}
    assert [(r["rule"], r["hits"]) for r in facets["rules"]] == [
        ("r_login", 2),
        ("r_pt1", 1),
    ]
