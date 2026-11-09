"""Analysts upload and delete YARA rule files from the dashboard.

Uploads are stored in the database, validated against the bundled rules and the
response catalogue before they are saved, and loaded without a restart.
"""

import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

# routes.* pull in the optional AI client, irrelevant here.
if "aiohttp" not in sys.modules:
    aiohttp_stub = types.ModuleType("aiohttp")
    aiohttp_stub.ClientSession = object
    aiohttp_stub.ClientTimeout = object
    aiohttp_stub.ClientError = Exception
    sys.modules["aiohttp"] = aiohttp_stub

import custom_rules  # noqa: E402
import detection  # noqa: E402
from custom_rules import RuleUploadError  # noqa: E402
from database import get_database, initialize_database  # noqa: E402
from detection import YaraDetectionEngine  # noqa: E402

RULES = ROOT / "rules"
CONFIG = SimpleNamespace(
    yara_rules_path=str(RULES), responses_path=str(ROOT / "responses")
)


def rule(name="krawl_custom_acme_probe", strings='$a = "/acme-secret-panel"', meta=""):
    return f"""rule {name} {{
    meta:
        attack_type = "acme_probe"
        classification = "attack"
        severity = 6
        {meta}
    strings:
        {strings}
    condition:
        scan_target == "path" and any of them
}}
"""


@pytest.fixture
def live(tmp_path, monkeypatch):
    """A fresh database and a live detector with the bundled rules only."""
    initialize_database(str(tmp_path / "custom.db"))
    monkeypatch.setattr(detection, "_coordinator", None)
    monkeypatch.setattr(detection, "_catalog", None)
    monkeypatch.setattr(custom_rules, "_loaded_fingerprint", None)
    monkeypatch.setattr("config.get_config", lambda: CONFIG)
    detection.initialize_detection(CONFIG)
    return detection


def fired(path):
    return {f.rule_name for f in detection.get_detection().iter_findings(path=path)}


# --- engine ---------------------------------------------------------------------


def test_engine_loads_uploaded_sources_next_to_bundled_rules():
    engine = YaraDetectionEngine(RULES, uploaded={"acme.yar": rule()})
    coordinator = detection.DetectionCoordinator(engine)
    rows = {row["rule"]: row for row in coordinator.list_rules()}

    assert rows["krawl_custom_acme_probe"]["rule_file"] == "uploaded/acme"
    assert rows["krawl_custom_acme_probe"]["uploaded"] is True
    assert rows["krawl_sql_injection"]["uploaded"] is False
    assert engine.rule_strings["krawl_custom_acme_probe"] == frozenset({"$a"})
    assert {
        f.rule_name for f in coordinator.iter_findings(path="/acme-secret-panel")
    } == {"krawl_custom_acme_probe"}


# --- upload --------------------------------------------------------------------


def test_upload_is_stored_and_live_without_restart(live):
    assert "krawl_custom_acme_probe" not in fired("/acme-secret-panel")

    names = custom_rules.upload("acme.yar", rule())

    assert names == ["krawl_custom_acme_probe"]
    assert "krawl_custom_acme_probe" in fired("/acme-secret-panel")
    [stored] = custom_rules.list_files()
    assert stored["filename"] == "acme.yar"
    assert stored["rules"] == ["krawl_custom_acme_probe"]
    assert custom_rules.get_source("acme.yar") == rule()


def test_reupload_replaces_the_file(live):
    custom_rules.upload("acme.yar", rule())
    custom_rules.upload("acme.yar", rule(strings='$a = "/acme-other-panel"'))

    assert "krawl_custom_acme_probe" in fired("/acme-other-panel")
    assert "krawl_custom_acme_probe" not in fired("/acme-secret-panel")
    assert len(custom_rules.list_files()) == 1


BAD_UPLOADS = [
    ("../escape.yar", rule(), "file name"),
    ("acme.txt", rule(), "file name"),
    ("acme.yar", "", "empty"),
    ("acme.yar", "x" * (custom_rules.MAX_RULE_FILE_BYTES + 1), "256 KB"),
    ("acme.yar", rule().replace("condition:", "condition"), "line"),
    ("acme.yar", 'import "pe"\n' + rule(), "import"),
    ("acme.yar", 'include "/etc/passwd"\n' + rule(), "include"),
    ("acme.yar", 'import"console"\n' + rule(), "import"),
    ("acme.yar", '/* x */ import "console"\n' + rule(), "import"),
    ("acme.yar", rule(name="krawl_sql_injection"), "krawl_sql_injection"),
    ("acme.yar", rule().replace('attack_type = "acme_probe"', ""), "attack_type"),
    ("acme.yar", rule(meta='response_type = "no_such_reply"'), "no_such_reply"),
    ("acme.yar", "// only a comment\n", "no rules"),
]


@pytest.mark.parametrize("filename, source, message", BAD_UPLOADS)
def test_invalid_upload_is_rejected_and_nothing_changes(
    live, filename, source, message
):
    before = detection.get_detection()

    with pytest.raises(RuleUploadError, match=message):
        custom_rules.upload(filename, source)

    assert custom_rules.list_files() == []
    assert detection.get_detection() is before


def test_two_uploads_cannot_share_a_rule_name(live):
    custom_rules.upload("acme.yar", rule())

    with pytest.raises(RuleUploadError, match="krawl_custom_acme_probe"):
        custom_rules.upload("other.yar", rule())


def test_a_stem_cannot_be_uploaded_twice(live):
    # acme.yar and acme.yara would both show as uploaded/acme.
    custom_rules.upload("acme.yar", rule())

    with pytest.raises(RuleUploadError, match="acme.yar"):
        custom_rules.upload("acme.yara", rule(name="krawl_custom_other"))


def test_slow_rules_are_rejected(live, monkeypatch):
    monkeypatch.setattr(custom_rules, "MAX_SCAN_MS", -1)

    with pytest.raises(RuleUploadError, match="slow"):
        custom_rules.upload("acme.yar", rule())


# --- delete and reload ------------------------------------------------------------


def test_delete_removes_the_rules(live):
    custom_rules.upload("acme.yar", rule())

    assert custom_rules.delete("acme.yar") is True
    assert "krawl_custom_acme_probe" not in fired("/acme-secret-panel")
    assert custom_rules.list_files() == []
    assert custom_rules.delete("acme.yar") is False


def test_running_tracker_scans_with_uploaded_rules(live):
    # The app builds its tracker at startup, before any upload.
    from tracker import AccessTracker

    tracker = AccessTracker(100, 60)
    custom_rules.upload("acme.yar", rule())

    findings = tracker.detector.scan_request(path="/acme-secret-panel")
    assert "krawl_custom_acme_probe" in {f.rule_name for f in findings}


def test_other_replicas_pick_up_changes(live):
    # Another pod writes the row; this one only sees the database.
    custom_rules._store("acme.yar", rule(), ["krawl_custom_acme_probe"])

    assert custom_rules.reload_if_changed() is True
    assert "krawl_custom_acme_probe" in fired("/acme-secret-panel")
    assert custom_rules.reload_if_changed() is False


def test_concurrent_upload_elsewhere_is_picked_up(live, monkeypatch):
    # This pod read the stored files before another pod saved other.yar.
    custom_rules._store(
        "other.yar",
        rule(name="krawl_custom_other", strings='$a = "/other-panel"'),
        ["krawl_custom_other"],
    )
    real = custom_rules.stored_sources
    monkeypatch.setattr(custom_rules, "stored_sources", lambda: {})
    custom_rules.upload("acme.yar", rule())
    monkeypatch.setattr(custom_rules, "stored_sources", real)

    assert "krawl_custom_other" not in fired("/other-panel")
    assert custom_rules.reload_if_changed() is True
    assert "krawl_custom_other" in fired("/other-panel")
    assert "krawl_custom_acme_probe" in fired("/acme-secret-panel")


def test_startup_survives_a_database_error(live, monkeypatch, caplog):
    def broken():
        raise RuntimeError("database is down")

    monkeypatch.setattr(custom_rules, "_rows", broken)

    detection.initialize_detection(CONFIG)

    assert "krawl_sql_injection" in {
        r["rule"] for r in detection.get_detection().list_rules()
    }
    assert "database is down" in caplog.text


def test_sqlite_to_postgres_migration_copies_uploaded_rules():
    text = (ROOT / "scripts/migrate_sqlite_to_postgres.py").read_text()

    assert '("custom_yara_rules", CustomYaraRule)' in text


def test_startup_skips_a_stored_file_that_no_longer_compiles(live, caplog):
    custom_rules._store("good.yar", rule(), ["krawl_custom_acme_probe"])
    custom_rules._store("broken.yar", "rule broken {", ["broken"])

    detection.initialize_detection(CONFIG)

    assert "krawl_custom_acme_probe" in fired("/acme-secret-panel")
    assert "broken.yar" in caplog.text


# --- API and panel ---------------------------------------------------------------


@pytest.fixture
def client(live):
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient

    from routes import api, htmx

    app = FastAPI()
    app.state.config = SimpleNamespace(dashboard_secret_path="dash")  # noqa: S106

    @app.exception_handler(api.Unauthorized)
    async def unauthorized(request, exc):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    app.include_router(api.router, prefix="/dash")
    app.include_router(htmx.router, prefix="/dash")
    return TestClient(app), app, api


def test_api_requires_auth(client):
    test_client, _, _ = client

    assert (
        test_client.post(
            "/dash/api/rules/upload", json={"filename": "a.yar", "content": rule()}
        ).status_code
        == 401
    )
    assert test_client.delete("/dash/api/rules/a.yar").status_code == 401
    assert test_client.get("/dash/api/rules/a.yar").status_code == 401


def test_api_upload_download_delete(client):
    test_client, app, api = client
    app.dependency_overrides[api.require_auth] = lambda: None

    ok = test_client.post(
        "/dash/api/rules/upload", json={"filename": "acme.yar", "content": rule()}
    )
    assert ok.status_code == 200
    assert ok.json() == {
        "ok": True,
        "filename": "acme.yar",
        "rules": ["krawl_custom_acme_probe"],
    }

    bad = test_client.post(
        "/dash/api/rules/upload", json={"filename": "bad.yar", "content": "rule x {"}
    )
    assert bad.status_code == 400
    assert "line" in bad.json()["error"]

    download = test_client.get("/dash/api/rules/acme.yar")
    assert download.status_code == 200
    assert download.text == rule()
    assert "attachment" in download.headers["content-disposition"]

    assert test_client.delete("/dash/api/rules/acme.yar").status_code == 200
    assert test_client.delete("/dash/api/rules/acme.yar").status_code == 404
    assert test_client.get("/dash/api/rules/acme.yar").status_code == 404


def test_panel_lists_uploaded_files_with_actions(client, monkeypatch):
    test_client, _, _ = client
    from routes import htmx

    monkeypatch.setattr(htmx, "verify_auth", lambda request: True)
    custom_rules.upload("acme.yar", rule())

    panel = test_client.get("/dash/htmx/rules").text

    assert "rulesUploader(" in panel
    assert "acme.yar" in panel
    assert "deleteRuleFile(" in panel
    assert "read-only" not in panel
    table = test_client.get("/dash/htmx/rules/table", params={"q": "acme"}).text
    assert "uploaded/acme.yar" in table


def test_custom_rules_table_is_created(live):
    from sqlalchemy import inspect

    assert "custom_yara_rules" in inspect(get_database().engine).get_table_names()
