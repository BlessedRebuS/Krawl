"""Rule metadata shown to analysts next to a stored request."""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import detection
from database import get_database, initialize_database
from detection import DetectionCoordinator, YaraDetectionEngine
from models import AccessLog, AttackDetection

RULES = Path(__file__).resolve().parent.parent / "rules"


@pytest.fixture(scope="module")
def yara_detector():
    return DetectionCoordinator(YaraDetectionEngine(RULES))


def test_describe_returns_the_rule_metadata_for_an_attack_type(yara_detector):
    details = yara_detector.describe_attack_types(["cve_2022_22965"])

    [rule] = details["cve_2022_22965"]
    assert rule["rule"] == "krawl_cve_2022_22965_spring4shell"
    assert rule["rule_file"] == "cve_enterprise"
    assert rule["severity"] == 10
    assert rule["confidence"] == "high"
    assert rule["classification"] == "attack"
    assert rule["mitre_attack"] == ["T1190"]
    assert rule["cve"] == ["CVE-2022-22965"]
    assert rule["references"] == ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"]
    assert "classLoader" in rule["description"]
    assert rule["false_positives"]


def test_describe_splits_list_fields(yara_detector):
    [rule] = yara_detector.describe_attack_types(["command_injection"])[
        "command_injection"
    ]

    assert rule["mitre_attack"] == ["T1190", "T1059.004"]
    assert rule["cve"] == []


def test_describe_lists_every_rule_sharing_an_attack_type(yara_detector):
    rules = yara_detector.describe_attack_types(["path_traversal"])["path_traversal"]

    assert {rule["rule"] for rule in rules} == {
        "krawl_path_traversal",
        "krawl_path_traversal_evasion",
    }


def test_describe_unknown_type_is_empty(yara_detector):
    assert yara_detector.describe_attack_types(["no_such_type"]) == {"no_such_type": []}


@pytest.fixture
def stored_log(tmp_path):
    initialize_database(str(tmp_path / "details.db"))
    db = get_database()
    session = db.session
    log = AccessLog(
        ip="203.0.113.7",
        path="/app/index",
        user_agent="Mozilla/5.0",
        method="POST",
        is_suspicious=True,
        is_honeypot_trigger=False,
        raw_request="POST /app/index HTTP/1.1\r\n\r\nclass.module.classLoader.x=1",
    )
    session.add(log)
    session.flush()
    session.add_all(
        [
            AttackDetection(
                access_log_id=log.id,
                attack_type="command_injection",
                matched_pattern="cmd=",
            ),
            AttackDetection(
                access_log_id=log.id,
                attack_type="cve_2022_22965",
                matched_pattern="class.module.classLoader.",
            ),
        ]
    )
    session.commit()
    log_id = log.id
    db.close_session()
    return log_id


def test_detections_for_a_log_are_read_back(stored_log):
    rows = get_database().access_logs.get_attack_detections_by_log_id(stored_log)

    assert sorted(rows, key=lambda row: row["attack_type"]) == [
        {
            "attack_type": "command_injection",
            "matched_pattern": "cmd=",
            "rule_name": None,
        },
        {
            "attack_type": "cve_2022_22965",
            "matched_pattern": "class.module.classLoader.",
            "rule_name": None,
        },
    ]


def test_raw_request_api_returns_detections_with_rule_details(
    stored_log, yara_detector, monkeypatch
):
    from routes import api

    monkeypatch.setattr(detection, "_coordinator", yara_detector)

    response = asyncio.run(api.raw_request(stored_log, SimpleNamespace()))
    data = json.loads(response.body)

    assert data["raw_request"].startswith("POST /app/index")
    # Highest severity first, so the most serious match leads the legend.
    assert [item["attack_type"] for item in data["detections"]] == [
        "cve_2022_22965",
        "command_injection",
    ]
    spring = data["detections"][0]
    assert spring["matched_pattern"] == "class.module.classLoader."
    assert spring["severity"] == 10
    assert spring["rules"][0]["rule"] == "krawl_cve_2022_22965_spring4shell"


def test_raw_request_api_without_detections_returns_an_empty_list(
    tmp_path, yara_detector, monkeypatch
):
    from routes import api

    initialize_database(str(tmp_path / "plain.db"))
    db = get_database()
    session = db.session
    log = AccessLog(
        ip="203.0.113.8",
        path="/",
        user_agent="Mozilla/5.0",
        method="GET",
        is_suspicious=False,
        is_honeypot_trigger=False,
        raw_request="GET / HTTP/1.1\r\n\r\n",
    )
    session.add(log)
    session.commit()
    log_id = log.id
    db.close_session()
    monkeypatch.setattr(detection, "_coordinator", yara_detector)

    data = json.loads(asyncio.run(api.raw_request(log_id, SimpleNamespace())).body)

    assert data["detections"] == []


def test_only_http_references_are_exposed(tmp_path):
    (tmp_path / "refs.yar").write_text(
        'rule krawl_test_refs { meta: attack_type = "refs" classification = "attack" '
        'severity = 5 reference = "javascript:alert(1), https://example.com/a, '
        'http://example.com/b" strings: $a = "needle-text" condition: $a }',
        encoding="utf-8",
    )
    detector = DetectionCoordinator(YaraDetectionEngine(tmp_path))

    [rule] = detector.describe_attack_types(["refs"])["refs"]

    assert rule["references"] == ["https://example.com/a", "http://example.com/b"]
