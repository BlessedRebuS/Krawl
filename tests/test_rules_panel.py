"""The dashboard Rules panel lists every loaded YARA rule with its match counts."""

import sys
import types
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import inspect

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

# routes.* pull in the optional AI client, irrelevant here.
if "aiohttp" not in sys.modules:
    aiohttp_stub = types.ModuleType("aiohttp")
    aiohttp_stub.ClientSession = object
    aiohttp_stub.ClientTimeout = object
    aiohttp_stub.ClientError = Exception
    sys.modules["aiohttp"] = aiohttp_stub

from database import get_database, initialize_database  # noqa: E402
from detection import DetectionCoordinator, YaraDetectionEngine  # noqa: E402
from models import AccessLog, AttackDetection  # noqa: E402

RULES = ROOT / "rules"
NOW = datetime(2026, 10, 27, 12, 0, 0)


@pytest.fixture(scope="module")
def coordinator():
    return DetectionCoordinator(YaraDetectionEngine(RULES))


def _rule(name, attack_type, severity=5, rule_file="web_attacks", **extra):
    return {
        "rule": name,
        "rule_file": rule_file,
        "attack_type": attack_type,
        "classification": extra.get("classification", "attack"),
        "severity": severity,
        "confidence": "high",
        "description": f"{name} description",
        "mitre_attack": [],
        "cve": extra.get("cve", []),
        "references": [],
        "false_positives": "",
        "response_type": extra.get("response_type", ""),
    }


def _rows(rules, by_rule=None, unnamed_by_type=None, **query):
    from routes.htmx import build_rule_rows

    stats = {"by_rule": by_rule or {}, "unnamed_by_type": unnamed_by_type or {}}
    return build_rule_rows(rules, stats, **query)


# --- rule metadata ---------------------------------------------------------------


def test_list_rules_returns_every_loaded_rule(coordinator):
    rules = coordinator.list_rules()
    names = [rule["rule"] for rule in rules]

    assert len(names) == len(set(names)) == 3259
    by_name = {rule["rule"]: rule for rule in rules}
    assert by_name["krawl_sql_injection"]["response_type"] == "sql_error"
    assert by_name["krawl_common_probes"]["response_type"] == ""
    for rule in rules:
        assert {"rule_file", "attack_type", "severity", "classification"} <= set(rule)


# --- match counts ------------------------------------------------------------


def _store(rows):
    """rows: (attack_type, rule_name, age_minutes)."""
    db = get_database()
    s = db.session
    for attack_type, rule_name, age in rows:
        log = AccessLog(
            ip="198.51.100.70",
            path="/x",
            method="GET",
            is_suspicious=True,
            timestamp=NOW - timedelta(minutes=age),
        )
        s.add(log)
        s.flush()
        s.add(
            AttackDetection(
                access_log_id=log.id, attack_type=attack_type, rule_name=rule_name
            )
        )
    s.commit()
    db.close_session()


def test_rule_match_stats(tmp_path):
    initialize_database(str(tmp_path / "s.db"))
    _store(
        [
            ("sql_injection", "krawl_sql_injection", 30),
            ("sql_injection", "krawl_sql_injection", 5),
            ("xss_attempt", None, 10),
            ("path_traversal", None, 1),
        ]
    )

    stats = get_database().access_logs.get_rule_match_stats()

    assert stats["by_rule"]["krawl_sql_injection"] == (2, NOW - timedelta(minutes=5))
    assert stats["unnamed_by_type"]["xss_attempt"] == (1, NOW - timedelta(minutes=10))
    assert stats["unnamed_by_type"]["path_traversal"][0] == 1
    assert None not in stats["by_rule"]


def test_rule_name_index_is_created(tmp_path):
    initialize_database(str(tmp_path / "i.db"))

    indexes = {
        item["name"]
        for item in inspect(get_database().engine).get_indexes("attack_detections")
    }
    assert "ix_attack_detections_rule_name" in indexes


# --- rows ----------------------------------------------------------------------


SQL = _rule("krawl_sql_injection", "sql_injection", 8, response_type="sql_error")
XSS = _rule("krawl_xss_attempt", "xss_attempt", 7, rule_file="web_attacks")
PT = _rule("krawl_path_traversal", "path_traversal", 8)
PT_EVASION = _rule("krawl_path_traversal_evasion", "path_traversal", 7)
UA = _rule(
    "krawl_scanner_user_agent",
    "scanner_user_agent",
    4,
    rule_file="scanners",
    classification="suspicious",
)
ALL = [SQL, XSS, PT, PT_EVASION, UA]


def _by_name(rows):
    return {row["rule"]: row for row in rows}


def test_named_matches_are_counted():
    rows = _by_name(_rows(ALL, by_rule={"krawl_sql_injection": (3, NOW)}))

    assert rows["krawl_sql_injection"]["matches"] == 3
    assert rows["krawl_sql_injection"]["last_match"] == NOW


def test_unnamed_detection_of_unique_type_is_attributed():
    older = NOW - timedelta(days=1)
    rows = _by_name(
        _rows(
            ALL,
            by_rule={"krawl_xss_attempt": (1, older)},
            unnamed_by_type={"xss_attempt": (4, NOW)},
        )
    )

    assert rows["krawl_xss_attempt"]["matches"] == 5
    assert rows["krawl_xss_attempt"]["last_match"] == NOW


def test_unnamed_detection_of_shared_type_is_not_attributed():
    rows = _by_name(_rows(ALL, unnamed_by_type={"path_traversal": (9, NOW)}))

    assert rows["krawl_path_traversal"]["matches"] == 0
    assert rows["krawl_path_traversal_evasion"]["matches"] == 0


def test_rows_without_detections():
    rows = _rows(ALL)

    assert len(rows) == len(ALL)
    assert all(row["matches"] == 0 and row["last_match"] is None for row in rows)


def test_filters_and_sort():
    names = lambda rows: [row["rule"] for row in rows]  # noqa: E731
    stats = {"krawl_xss_attempt": (5, NOW), "krawl_sql_injection": (2, NOW)}

    assert names(_rows(ALL, by_rule=stats))[:2] == [
        "krawl_xss_attempt",
        "krawl_sql_injection",
    ]
    assert names(_rows(ALL, rule_file="scanners")) == ["krawl_scanner_user_agent"]
    assert names(_rows(ALL, classification="suspicious")) == [
        "krawl_scanner_user_agent"
    ]
    assert set(names(_rows(ALL, min_severity="8"))) == {
        "krawl_sql_injection",
        "krawl_path_traversal",
    }
    ascending = [
        row["severity"] for row in _rows(ALL, sort_by="severity", sort_order="asc")
    ]
    assert ascending == sorted(ascending)


def test_search_matches_name_type_file_description_and_cve():
    cve_rule = _rule(
        "krawl_cve_2024_3400_panos", "cve_2024_3400", 10, cve=["CVE-2024-3400"]
    )
    rules = [*ALL, cve_rule]
    names = lambda **q: {row["rule"] for row in _rows(rules, **q)}  # noqa: E731

    assert names(q="SQL_INJ") == {"krawl_sql_injection"}
    assert names(q="scanners") == {"krawl_scanner_user_agent"}
    assert names(q="xss_attempt description") == {"krawl_xss_attempt"}
    assert names(q="cve-2024-3400") == {"krawl_cve_2024_3400_panos"}
    assert names(q="  ") == {row["rule"] for row in rules}
    assert names(q="no such rule") == set()


def test_rows_are_paginated():
    from routes.htmx import paginate_rule_rows

    rows = [{"rule": f"r{i}"} for i in range(120)]

    first, page, pages = paginate_rule_rows(rows, "1", per_page=50)
    assert [r["rule"] for r in first] == [f"r{i}" for i in range(50)]
    assert (page, pages) == (1, 3)
    last, page, pages = paginate_rule_rows(rows, "3", per_page=50)
    assert len(last) == 20 and page == 3
    # Out-of-range and junk pages are clamped, never an error.
    assert paginate_rule_rows(rows, "99", per_page=50)[1] == 3
    assert paginate_rule_rows(rows, "-4", per_page=50)[1] == 1
    assert paginate_rule_rows(rows, "x", per_page=50)[1] == 1
    assert paginate_rule_rows([], "1", per_page=50) == ([], 1, 1)


def test_bad_query_values_fall_back():
    default = [row["rule"] for row in _rows(ALL)]

    rows = _rows(ALL, sort_by="drop table", sort_order="sideways", min_severity="x")

    assert [row["rule"] for row in rows] == default


# --- routes and wiring -----------------------------------------------------------


@pytest.fixture
def client(tmp_path, monkeypatch, coordinator):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    import detection
    from routes import htmx

    initialize_database(str(tmp_path / "r.db"))
    monkeypatch.setattr(detection, "_coordinator", coordinator)
    app = FastAPI()
    app.state.config = SimpleNamespace(dashboard_secret_path="dash")  # noqa: S106
    app.include_router(htmx.router, prefix="/dash")
    return TestClient(app)


@pytest.mark.parametrize("url", ["/dash/htmx/rules", "/dash/htmx/rules/table"])
def test_rules_routes_require_auth(client, monkeypatch, url):
    from routes import htmx

    response = client.get(url)
    assert response.status_code == 401
    assert "401 Unauthorized" in response.text

    monkeypatch.setattr(htmx, "verify_auth", lambda request: True)
    response = client.get(url, params={"q": "krawl_sql_injection"})
    assert response.status_code == 200
    assert "krawl_sql_injection" in response.text
    assert "sql_error" in response.text


def test_rules_table_sends_one_page(client, monkeypatch):
    from routes import htmx

    monkeypatch.setattr(htmx, "verify_auth", lambda request: True)
    first = client.get("/dash/htmx/rules/table").text
    second = client.get("/dash/htmx/rules/table", params={"page": "2"}).text

    assert first.count('class="rules-row"') == htmx.RULES_PER_PAGE
    assert "page=2" in first
    assert first != second


def test_search_is_sent_to_the_server():
    panel = (
        ROOT / "src/templates/jinja2/dashboard/partials/rules_panel.html"
    ).read_text()
    table = (
        ROOT / "src/templates/jinja2/dashboard/partials/rules_table.html"
    ).read_text()

    assert 'name="q"' in panel
    assert "data-search" not in table


def test_rules_tab_is_wired_in_js():
    js = (ROOT / "src/templates/static/js/dashboard.js").read_text()
    header = (ROOT / "src/templates/jinja2/dashboard/partials/_header.html").read_text()
    index = (ROOT / "src/templates/jinja2/dashboard/index.html").read_text()

    assert "switchToRules()" in js
    assert "'rules': () => this.switchToRules()" in js
    assert "hash === 'rules'" in js
    assert "nav('rules'" in header
    assert "rules-htmx-container" in index
