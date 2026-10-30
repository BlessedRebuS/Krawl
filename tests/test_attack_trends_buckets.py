"""Trends fold hourly detections into 1h/4h/1d buckets and report slot totals."""

from datetime import datetime, timedelta

import pytest

from database import get_database, initialize_database
from models import AccessLog, AttackDetection
from period import resolve_period, slot_labels


@pytest.fixture
def db(tmp_path):
    initialize_database(str(tmp_path / "x.db"))
    return get_database()


def _add(db, ts, attack_type):
    s = db.session
    log = AccessLog(ip="203.0.113.1", path="/", method="GET", is_suspicious=True, timestamp=ts)
    s.add(log)
    s.flush()
    s.add(AttackDetection(access_log_id=log.id, attack_type=attack_type))
    s.commit()
    db.close_session()


def test_7d_is_four_hour_buckets_and_sums_hours(db):
    labels = slot_labels(resolve_period(7))
    assert len(labels) in (42, 43)  # 43 when now is off the 4h grid
    base = datetime.strptime(labels[-3], "%Y-%m-%dT%H")
    _add(db, base + timedelta(hours=1), "xss")
    _add(db, base + timedelta(hours=3), "xss")
    _add(db, base + timedelta(hours=5), "xss")  # next bucket
    r = db.analytics.get_attack_types_daily(days=7)
    assert r["bucket_hours"] == 4
    assert r["dates"] == labels
    assert r["attack_types"][0]["daily"][-3:-1] == [2, 1]
    assert r["slot_totals"] is None
    assert "xss" in r["colours"]


def test_30d_is_daily(db):
    r = db.analytics.get_attack_types_daily(days=30)
    assert r["bucket_hours"] == 24
    assert all(d.endswith("T00") for d in r["dates"])


def test_slot_totals_count_only_that_bucket(db):
    labels = slot_labels(resolve_period(7))
    base = datetime.strptime(labels[-3], "%Y-%m-%dT%H")
    _add(db, base + timedelta(hours=1), "xss")
    _add(db, base + timedelta(hours=2), "sqli")
    _add(db, base + timedelta(hours=2), "sqli")
    _add(db, base + timedelta(hours=5), "rfi")
    r = db.analytics.get_attack_types_daily(days=7, slot=labels[-3])
    assert r["slot_totals"] == [{"type": "sqli", "total": 2}, {"type": "xss", "total": 1}]
    assert set(r["colours"]) >= {"sqli", "xss", "rfi"}
