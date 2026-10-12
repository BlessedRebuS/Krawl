"""Isolate legacy script-style tests that share process-wide services."""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


@pytest.fixture(autouse=True)
def isolate_services(monkeypatch):
    import config
    import dashboard_cache
    from database import get_database

    environment = os.environ.copy()
    db = get_database()
    if db._initialized:
        db.close_session()
        db.engine.dispose()
        db._initialized = False
    monkeypatch.setattr(config, "_config_instance", None)
    monkeypatch.setattr(dashboard_cache, "_backend", "standalone")
    monkeypatch.setattr(dashboard_cache, "_redis_client", None)
    monkeypatch.setattr(dashboard_cache, "_cache", {})
    yield
    if db._initialized:
        db.close_session()
        db.engine.dispose()
        db._initialized = False
    os.environ.clear()
    os.environ.update(environment)
