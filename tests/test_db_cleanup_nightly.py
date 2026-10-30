"""Database cleanup runs as a nightly task, not on the boot path."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import tasks.db_cleanup as db_cleanup  # noqa: E402


def test_app_startup_does_not_run_cleanup():
    assert "run_startup_cleanup" not in (ROOT / "src" / "app.py").read_text()


def test_task_runs_nightly_on_one_pod():
    cfg = db_cleanup.TASK_CONFIG
    assert cfg["cron"] == "0 3 * * *"
    assert cfg["run_when_loaded"] is False
    assert cfg["single_pod"] is True


def test_main_runs_the_cleanup_with_config(monkeypatch):
    calls = []
    cfg = type(
        "C",
        (),
        {
            "ban_duration_seconds": 600,
            "ignored_ips": ["10.0.0.0/8"],
            "ipv6_ignore": True,
            "ipv6_purge_existing": False,
        },
    )()
    monkeypatch.setattr(db_cleanup, "get_config", lambda: cfg)
    monkeypatch.setattr(db_cleanup, "get_database", lambda: "db")
    monkeypatch.setattr(
        db_cleanup, "run_startup_cleanup", lambda *a, **k: calls.append((a, k))
    )
    db_cleanup.main()
    assert calls == [(("db", 600, ["10.0.0.0/8"]), {"purge_ipv6": False})]
