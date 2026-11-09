"""Each attack detection stores the YARA rule that matched; old rows keep working."""

import sys
import types
from pathlib import Path

from sqlalchemy import inspect, text

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# routes.api pulls in the optional AI client, irrelevant here.
if "aiohttp" not in sys.modules:
    aiohttp_stub = types.ModuleType("aiohttp")
    aiohttp_stub.ClientSession = object
    aiohttp_stub.ClientTimeout = object
    aiohttp_stub.ClientError = Exception
    sys.modules["aiohttp"] = aiohttp_stub

from database import get_database, initialize_database  # noqa: E402
from detection import DetectionFinding  # noqa: E402
from models import AttackDetection  # noqa: E402

IP = "198.51.100.61"


def _reopen(db_path):
    db = get_database()
    if db._initialized:
        db.close_session()
        db.engine.dispose()
        db._initialized = False
    initialize_database(str(db_path))
    return get_database()


def _detections():
    db = get_database()
    rows = db.session.query(AttackDetection).all()
    result = [(row.attack_type, row.rule_name) for row in rows]
    db.close_session()
    return result


def test_old_database_gains_rule_name_column(tmp_path):
    db_path = tmp_path / "old.db"
    db = _reopen(db_path)
    # One detection, then drop the column: a database from before this change.
    db.persist_access(
        ip=IP, path="/old", is_suspicious=True, attack_types=["path_traversal"]
    )
    with db.engine.begin() as conn:
        conn.execute(text("DROP INDEX IF EXISTS ix_attack_detections_rule_name"))
        conn.execute(text("ALTER TABLE attack_detections DROP COLUMN rule_name"))
    assert "rule_name" not in {
        c["name"] for c in inspect(db.engine).get_columns("attack_detections")
    }

    db = _reopen(db_path)

    columns = {c["name"] for c in inspect(db.engine).get_columns("attack_detections")}
    assert "rule_name" in columns
    indexes = {i["name"] for i in inspect(db.engine).get_indexes("attack_detections")}
    assert "ix_attack_detections_rule_name" in indexes
    assert _detections() == [("path_traversal", None)]


def test_direct_write_stores_rule_name(tmp_path):
    db = _reopen(tmp_path / "a.db")

    db.persist_access(
        ip=IP,
        path="/item",
        is_suspicious=True,
        attack_types=["sql_injection"],
        matched_patterns={"sql_injection": "' OR 1=1"},
        rule_names={"sql_injection": "krawl_sql_injection"},
    )

    assert _detections() == [("sql_injection", "krawl_sql_injection")]


def test_rule_name_is_truncated(tmp_path):
    db = _reopen(tmp_path / "a.db")

    db.persist_access(
        ip=IP,
        path="/item",
        is_suspicious=True,
        attack_types=["sql_injection"],
        rule_names={"sql_injection": "r" * 300},
    )

    assert _detections() == [("sql_injection", "r" * 128)]


def test_buffered_detection_keeps_rule_name(tmp_path):
    from database.core import _buffer_access_log_entry

    db = _reopen(tmp_path / "b.db")
    _buffer_access_log_entry(
        ip=IP,
        path="/item",
        user_agent="x",
        method="GET",
        is_suspicious=True,
        is_honeypot_trigger=False,
        attack_types=["sql_injection"],
        matched_patterns={"sql_injection": "' OR 1=1"},
        rule_names={"sql_injection": "krawl_sql_injection"},
        raw_request=None,
        referer=None,
        file_payloads=None,
        target_host=None,
        request_assets=None,
    )

    assert db.flush_access_log_buffer() == 1
    assert _detections() == [("sql_injection", "krawl_sql_injection")]


def test_tracker_passes_rule_names(tmp_path):
    from tracker import AccessTracker

    _reopen(tmp_path / "t.db")
    finding = DetectionFinding(
        attack_type="sql_injection",
        matched_pattern="' OR 1=1",
        source="yara",
        scan_target="query",
        severity=8,
        rule_name="krawl_sql_injection",
    )
    tracker = AccessTracker(100, 60, detector=object())

    tracker.record_access(
        ip=IP,
        path="/item",
        user_agent="Mozilla/5.0",
        query="id=1' OR 1=1",
        detection_findings=[finding],
    )

    assert _detections() == [("sql_injection", "krawl_sql_injection")]


def _describe(rule_name):
    from routes.api import _describe_detections

    [item] = _describe_detections(
        [
            {
                "attack_type": "path_traversal",
                "matched_pattern": "../",
                "rule_name": rule_name,
            }
        ]
    )
    return [rule["rule"] for rule in item["rules"]]


def test_stored_rule_name_selects_that_rule():
    assert _describe("krawl_path_traversal_evasion") == ["krawl_path_traversal_evasion"]


def test_unknown_rule_name_falls_back_to_type():
    every_rule = sorted(_describe(None))

    assert sorted(_describe("gone_rule")) == every_rule
    assert sorted(_describe("credential_fields")) == every_rule
    assert set(every_rule) == {"krawl_path_traversal", "krawl_path_traversal_evasion"}
