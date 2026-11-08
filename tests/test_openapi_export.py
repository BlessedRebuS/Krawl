"""docs/api/openapi.json (the docs site's API reference) matches the app."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import export_openapi  # noqa: E402


def test_committed_schema_is_current(monkeypatch):
    # schema() sets it; registering it here makes monkeypatch restore it.
    monkeypatch.setenv("KRAWL_DASHBOARD_SECRET_PATH", export_openapi.PLACEHOLDER)
    committed = json.loads(export_openapi.OUT.read_text())
    live = export_openapi.schema()
    assert committed == json.loads(json.dumps(live)), "run: python scripts/export_openapi.py"
