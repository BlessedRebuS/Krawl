"""Top paths / user agents are recomputed on the 30-minute schedule or when missing."""

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import dashboard_cache  # noqa: E402
from tasks import dashboard_warmup  # noqa: E402

NOT_SLOW = 300 * 7  # run 7: not a multiple of 6


@pytest.fixture
def warmup(monkeypatch):
    dashboard_cache.initialize_cache("standalone")
    dashboard_cache._cache.clear()
    monkeypatch.setattr(dashboard_warmup.time, "time", lambda: NOT_SLOW)
    monkeypatch.setattr(
        dashboard_warmup,
        "get_config",
        lambda: SimpleNamespace(
            dashboard_cache_warmup=True,
            dashboard_warmup_pages=1,
            dashboard_warmup_aggregation=True,
            dashboard_top_n_min_count=1,
        ),
    )
    db = MagicMock()
    db.analytics.get_top_paths.return_value = [("/a", 3)]
    db.analytics.get_top_user_agents.return_value = [("ua", 3)]
    monkeypatch.setattr(dashboard_warmup, "get_database", lambda: db)
    return db


def test_cached_rankings_are_not_recomputed_between_slow_runs(warmup):
    dashboard_cache.set_cached("top_paths", {"paths": []})
    dashboard_cache.set_cached("top_ua", {"user_agents": []})

    dashboard_warmup.main()

    warmup.analytics.get_top_paths.assert_not_called()
    warmup.analytics.get_top_user_agents.assert_not_called()


def test_missing_rankings_are_computed_at_once(warmup):
    dashboard_warmup.main()

    warmup.analytics.get_top_paths.assert_called_once()
    assert dashboard_cache.get_cached("top_paths")["paths"] == [
        {"path": "/a", "count": 3}
    ]
