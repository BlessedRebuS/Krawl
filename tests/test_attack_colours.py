"""Attack types map to a severity band and a stable shade."""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import detection  # noqa: E402
from attack_colours import (  # noqa: E402
    attack_badge_class,
    attack_band,
    attack_shade,
)

SEV = {"cve_x": 9, "path_traversal": 8, "login_attempt": 4, "common_probes": 2}


@pytest.fixture
def stub(monkeypatch):
    coord = SimpleNamespace(attack_type_severity=lambda t: SEV.get(t, 0))
    monkeypatch.setattr(detection, "loaded_detection", lambda: coord)


def test_bands(stub):
    assert [attack_band(t) for t in SEV] == ["critical", "high", "medium", "low"]


def test_unknown_type_is_low(stub):
    assert attack_band("no_such_rule") == "low"


def test_no_detection_loaded_is_low(monkeypatch):
    monkeypatch.setattr(detection, "loaded_detection", lambda: None)
    assert attack_band("cve_x") == "low"


def test_shade_is_stable_and_in_range():
    assert attack_shade("wp_user_enum") == attack_shade(" WP_USER_ENUM ")
    assert {attack_shade(f"t{i}") for i in range(200)} == {1, 2, 3, 4}


def test_badge_class(stub):
    assert (
        attack_badge_class("cve_x")
        == f"atk-badge atk-sev-critical atk-shade-{attack_shade('cve_x')}"
    )


def test_attack_types_daily_carries_colours(stub, tmp_path):
    from datetime import datetime

    from database import get_database, initialize_database
    from models import AccessLog, AttackDetection

    initialize_database(str(tmp_path / "x.db"))
    db = get_database()
    s = db.session
    for t in SEV:
        log = AccessLog(ip="203.0.113.1", path="/", method="GET", is_suspicious=True, timestamp=datetime.utcnow())
        s.add(log)
        s.flush()
        s.add(AttackDetection(access_log_id=log.id, attack_type=t))
    s.commit()
    db.close_session()

    for result in (db.analytics.get_attack_types_daily(days=7), db.analytics.get_attack_types_stats()):
        types = {a["type"] for a in result["attack_types"]}
        assert types == set(SEV)
        assert set(result["colours"]) == types
        assert all(set(c) == {"band", "shade"} for c in result["colours"].values())
