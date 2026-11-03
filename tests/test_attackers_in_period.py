"""Attackers ranked by detections in a window, and range on credentials/honeypot/domains."""

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
from models import AccessLog, AttackDetection, CredentialAttempt, IpStats  # noqa: E402

NOW = datetime(2026, 10, 27, 12, 0, 0)
SINCE, UNTIL = NOW - timedelta(days=7), NOW
RULES = {
    "login_attempt": [{"rule": "r_login", "severity": 4}],
    "path_traversal": [{"rule": "r_pt", "severity": 7}],
}
A, B, C = "8.8.8.1", "8.8.8.2", "8.8.8.3"


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
    s.add(IpStats(ip=A, category="bad_crawler", city="Rome", country_code="IT"))
    s.add(IpStats(ip=B, category="attacker"))
    rows = [  # ip, attack_type, rule, age, host, honeypot
        (A, "path_traversal", None, timedelta(hours=1), "a.test", True),
        (A, "path_traversal", None, timedelta(hours=2), "a.test", True),
        (A, "login_attempt", "r_login", timedelta(hours=3), "b.test", False),
        (B, "login_attempt", "r_login", timedelta(hours=4), "a.test", True),
        (B, "login_attempt", "r_login", timedelta(days=20), "old.test", True),
        (C, "cve_x", None, timedelta(days=20), "old.test", False),
    ]
    for ip, atype, rule, age, host, hp in rows:
        log = AccessLog(
            ip=ip,
            path=f"/{atype}",
            method="GET",
            is_suspicious=True,
            is_honeypot_trigger=hp,
            target_host=host,
            timestamp=NOW - age,
        )
        s.add(log)
        s.flush()
        s.add(AttackDetection(access_log_id=log.id, attack_type=atype, rule_name=rule))
    for ip, age in [(A, timedelta(hours=1)), (A, timedelta(days=20))]:
        s.add(CredentialAttempt(ip=ip, path="/login", username="u", timestamp=NOW - age))
    s.commit()
    db.close_session()
    return db


def _attackers(db, **kw):
    return db.analytics.get_attackers_in_period(SINCE, UNTIL, **kw)


def test_ranks_by_detections_in_range_regardless_of_category(stored):
    r = _attackers(stored)
    assert [(a["ip"], a["hits"]) for a in r["attackers"]] == [(A, 3), (B, 1)]
    assert r["pagination"]["total"] == 2
    assert r["attackers"][0]["category"] == "bad_crawler"


def test_type_narrowing_counts_only_that_type(stored):
    r = _attackers(stored, attack_type="login_attempt")
    assert [(a["ip"], a["hits"]) for a in r["attackers"]] == [(A, 1), (B, 1)]
    r = _attackers(stored, rule="r_login")
    assert [(a["ip"], a["hits"]) for a in r["attackers"]] == [(A, 1), (B, 1)]


def test_rule_filter_credits_legacy_null_rule_rows_to_sole_rule(stored):
    s = stored.session
    log = AccessLog(ip=C, path="/x", method="GET", timestamp=NOW - timedelta(hours=1))
    s.add(log)
    s.flush()
    s.add(AttackDetection(access_log_id=log.id, attack_type="login_attempt"))
    s.commit()
    stored.close_session()
    r = _attackers(stored, rule="r_login")
    assert [(a["ip"], a["hits"]) for a in r["attackers"]] == [(A, 1), (B, 1), (C, 1)]


def test_top_type_tie_breaks_by_name(stored):
    s = stored.session
    log = AccessLog(ip=B, path="/x", method="GET", timestamp=NOW - timedelta(hours=1))
    s.add(log)
    s.flush()
    s.add(AttackDetection(access_log_id=log.id, attack_type="zz_type"))
    s.commit()
    stored.close_session()
    b = [a for a in _attackers(stored)["attackers"] if a["ip"] == B][0]
    assert b["top_type"] == "zz_type"


def test_worst_band_and_top_type(stored):
    a = _attackers(stored)["attackers"][0]
    assert a["top_type"] == "path_traversal"
    assert a["worst_band"] == "high"
    assert (a["city"], a["country_code"]) == ("Rome", "IT")


def test_credentials_and_honeypot_respect_range(stored):
    assert stored.credentials.get_paginated()["pagination"]["total"] == 2
    assert (
        stored.credentials.get_paginated(since=SINCE, until=UNTIL)["pagination"][
            "total"
        ]
        == 1
    )
    hp = stored.access_logs.get_honeypot_paginated(since=SINCE, until=UNTIL)
    assert sorted(h["ip"] for h in hp["honeypots"]) == [A, B]
    assert all(h["count"] == 1 for h in hp["honeypots"] if h["ip"] == B)
    assert stored.access_logs.get_honeypot_paginated()["pagination"]["total"] == 2


def test_targeted_domains_in_range_bypasses_rollup(stored):
    r = stored.access_logs.get_targeted_domains(since=SINCE, until=UNTIL)
    assert [(d["domain"], d["count"]) for d in r["domains"]] == [
        ("a.test", 3),
        ("b.test", 1),
    ]


def test_severity_filter_counts_only_detections_in_selected_bands(stored):
    out = _attackers(stored, severities=["high"])
    assert [(a["ip"], a["hits"]) for a in out["attackers"]] == [(A, 2)]
    assert _attackers(stored, severities=["critical"])["attackers"] == []
    both = _attackers(stored, severities=["high", "medium"])["attackers"]
    assert [(a["ip"], a["hits"]) for a in both] == [(A, 3), (B, 1)]


def test_attackers_route_parses_severity_filter():
    from routes.htmx import parse_severities

    assert parse_severities("High,bogus,high,low") == ["high", "low"]
    assert parse_severities(None) == []
