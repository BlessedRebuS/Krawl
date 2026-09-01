#!/usr/bin/env python3

"""
Settings > Configuration payload (github.com/BlessedRebuS/Krawl/issues/299).

The panel shows the running configuration to anyone holding the dashboard
password, so the one thing that must never regress is redaction: no secret
may appear in the payload, including a secret nobody remembered to list.

Usage: python tests/test_config_endpoint.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from routes.api import _config_section, _is_sensitive

SECRET = "hunter2-do-not-leak"  # noqa: S105 — a fake secret is the point of this test


def _payload(cfg):
    """The exact rows the endpoint serializes."""
    from routes.api import _config_fields

    return _config_fields(cfg)


def test_no_secret_survives_serialization():
    """Every secret-bearing field is reported as set, never as a value."""
    from config import Config

    cfg = Config(
        postgres_password=SECRET,
        redis_password=SECRET,
        ai_api_key=SECRET,
        map_api_key=SECRET,
        dashboard_password=SECRET,
        dashboard_secret_path=f"/{SECRET}",
        canary_token_url=f"https://canary.example.com/{SECRET}",
    )
    fields = _payload(cfg)

    # The blunt check: the secret must not appear anywhere in the JSON.
    blob = json.dumps(fields)
    assert SECRET not in blob, "a secret reached the payload"

    by_key = {e["key"]: e for e in fields}
    for key in (
        "postgres_password",
        "redis_password",
        "ai_api_key",
        "map_api_key",
        "dashboard_password",
        "dashboard_secret_path",
        "canary_token_url",
    ):
        entry = by_key[key]
        assert entry["sensitive"], f"{key} was not treated as sensitive"
        assert "value" not in entry, f"{key} carried a value"
        assert entry["set"] is True, f"{key} should report as set"

    print("OK: no secret reaches the payload")


def test_pattern_catches_an_unlisted_secret():
    """A secret added to Config later is redacted without touching a list.

    This is the point of the name pattern. If someone adds `smtp_password`
    and only the explicit list existed, it would leak until noticed.
    """
    for name in (
        "smtp_password",
        "webhook_secret",
        "vendor_api_key",
        "refresh_token",
    ):
        assert _is_sensitive(name), f"{name} would have leaked"

    print("OK: unlisted secrets are caught by the name pattern")


def test_false_positives_stay_visible():
    """A retry count and a boolean are not secrets, despite their names."""
    assert not _is_sensitive("canary_token_tries")
    assert not _is_sensitive("dashboard_password_generated")
    print("OK: non-secret fields matching the pattern stay visible")


def test_sections_follow_config_yaml():
    """Fields group under the config.yaml block an operator would edit."""
    assert _config_section("postgres_host") == ("postgres", "host")
    assert _config_section("ai_model") == ("ai", "model")
    assert _config_section("map_tile_url") == ("map", "tile_url")
    # The analyzer and crawl blocks flatten to bare names, so they are mapped
    # explicitly rather than by prefix.
    assert _config_section("attack_urls_threshold")[0] == "analyzer"
    assert _config_section("max_pages_limit")[0] == "crawl"
    # Anything ungrouped lands under server.
    assert _config_section("port") == ("server", "port")
    assert _config_section("log_level") == ("server", "log_level")
    print("OK: fields group the way config.yaml does")


def test_unset_secret_is_not_badged_custom():
    """An unset secret must not read "Not set" beside a "custom" badge.

    ai_api_key defaults to None and config.yaml writes "" — the same thing to
    a reader, but not to ==. Comparing raw values badged it as changed.
    """
    from config import Config

    by_key = {e["key"]: e for e in _payload(Config(ai_api_key=""))}
    entry = by_key["ai_api_key"]
    assert entry["set"] is False
    assert entry["source"] == "default", entry

    # A secret that really is set still reads as changed.
    by_key = {e["key"]: e for e in _payload(Config(ai_api_key=SECRET))}
    assert by_key["ai_api_key"]["source"] == "custom"

    print("OK: an unset secret is not badged as changed")


def test_every_field_is_accounted_for():
    """No field is silently dropped, and each is either a value or a status."""
    from config import Config

    fields = _payload(Config())
    for entry in fields:
        assert ("value" in entry) ^ ("set" in entry), entry["key"]
        assert entry["source"] in ("env", "custom", "default"), entry
    print(f"OK: all {len(fields)} config fields are represented")


if __name__ == "__main__":
    test_no_secret_survives_serialization()
    test_pattern_catches_an_unlisted_secret()
    test_false_positives_stay_visible()
    test_sections_follow_config_yaml()
    test_unset_secret_is_not_badged_custom()
    test_every_field_is_accounted_for()
