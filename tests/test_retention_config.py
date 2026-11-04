"""retention: section — duration parsing, legacy fallback, env precedence, panel."""

import os
import tempfile
from datetime import timedelta

import pytest

from config import Config, format_duration, override_config_from_env, parse_duration


def _load(yaml_text: str) -> Config:
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(yaml_text)
        path = fh.name
    os.environ["CONFIG_LOCATION"] = path
    try:
        cfg = Config.from_yaml()
        override_config_from_env(cfg)
        return cfg
    finally:
        os.unlink(path)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("12h", timedelta(hours=12)),
        ("30d", timedelta(days=30)),
        ("2w", timedelta(weeks=2)),
        ("6m", timedelta(days=180)),
        ("1y", timedelta(days=365)),
        (" 3D ", timedelta(days=3)),
        (14, timedelta(days=14)),
        ("14", timedelta(days=14)),
    ],
)
def test_parse_duration_units(value, expected):
    assert parse_duration(value, timedelta(days=1)) == expected


def test_parse_duration_missing_returns_default():
    assert parse_duration(None, timedelta(days=9)) == timedelta(days=9)
    assert parse_duration("", timedelta(days=9)) == timedelta(days=9)


def test_parse_duration_zero_disables():
    assert parse_duration(0, timedelta(days=9)) is None
    assert parse_duration("0", timedelta(days=9)) is None


@pytest.mark.parametrize("bad", ["abc", "10x", "-5d", True, "1.5d"])
def test_parse_duration_invalid_falls_back(bad):
    assert parse_duration(bad, timedelta(days=9)) == timedelta(days=9)


def test_format_duration_picks_largest_exact_unit():
    assert format_duration(timedelta(days=30)) == "30d"
    assert format_duration(timedelta(days=14)) == "2w"
    assert format_duration(timedelta(days=365)) == "1y"
    assert format_duration(timedelta(hours=36)) == "36h"


def test_defaults_from_empty_config():
    cfg = _load("{}\n")
    assert cfg.retention_non_suspicious == timedelta(days=30)
    assert cfg.retention_recheck_suspicious == timedelta(days=30)
    assert cfg.retention_reevaluate_interval == timedelta(days=5)
    assert cfg.retention_crunch_after == timedelta(days=7)
    assert cfg.retention_overall is None


def test_legacy_yaml_retention_days_drives_both_windows():
    cfg = _load("database:\n  retention_days: 10\n")
    assert cfg.retention_non_suspicious == timedelta(days=10)
    assert cfg.retention_recheck_suspicious == timedelta(days=10)


def test_new_yaml_key_beats_legacy_yaml_key():
    cfg = _load(
        "database:\n  retention_days: 10\n"
        "retention:\n  non-suspicious: 2w\n  overall: 1y\n"
    )
    assert cfg.retention_non_suspicious == timedelta(weeks=2)
    assert cfg.retention_recheck_suspicious == timedelta(days=10)
    assert cfg.retention_overall == timedelta(days=365)


def test_legacy_env_still_works(monkeypatch):
    monkeypatch.setenv("KRAWL_DATABASE_RETENTION_DAYS", "7")
    cfg = _load("retention:\n  non-suspicious: 30d\n")
    assert cfg.retention_non_suspicious == timedelta(days=7)
    assert cfg.retention_recheck_suspicious == timedelta(days=7)


def test_new_env_beats_legacy_env(monkeypatch):
    monkeypatch.setenv("KRAWL_DATABASE_RETENTION_DAYS", "7")
    monkeypatch.setenv("KRAWL_RETENTION_NON_SUSPICIOUS", "3d")
    cfg = _load("{}\n")
    assert cfg.retention_non_suspicious == timedelta(days=3)
    assert cfg.retention_recheck_suspicious == timedelta(days=7)


def test_env_empty_disables_overall(monkeypatch):
    monkeypatch.setenv("KRAWL_RETENTION_OVERALL", "")
    cfg = _load("retention:\n  overall: 1y\n")
    assert cfg.retention_overall is None


def test_settings_panel_renders_durations_as_defaults():
    from routes.api import _config_fields

    rows = {r["key"]: r for r in _config_fields(Config())}
    row = rows["retention_non_suspicious"]
    assert row["value"] == "30d"
    assert row["section"] == "retention"
    assert row["source"] == "default"
    assert rows["retention_overall"]["value"] is None


def test_invalid_legacy_env_does_not_override_yaml(monkeypatch):
    monkeypatch.setenv("KRAWL_DATABASE_RETENTION_DAYS", "")
    cfg = _load("retention:\n  non-suspicious: 90d\n")
    assert cfg.retention_non_suspicious == timedelta(days=90)


def test_blank_legacy_yaml_key_uses_default():
    cfg = _load("database:\n  retention_days:\n")
    assert cfg.retention_non_suspicious == timedelta(days=30)
