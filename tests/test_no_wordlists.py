"""A leftover wordlists.json is ignored, with one warning."""

import logging

WARNING = (
    "wordlists.json is no longer read; move proxy_headers, credential fields and "
    "scoring weights to config.yaml (see docs/honeypot.md)."
)


def test_leftover_wordlists_file_logs_one_warning(tmp_path, caplog):
    from app import warn_if_wordlists_present

    leftover = tmp_path / "wordlists.json"
    leftover.write_text("{}")

    with caplog.at_level(logging.WARNING):
        assert warn_if_wordlists_present([tmp_path / "missing.json", leftover])
    assert [r.getMessage() for r in caplog.records].count(WARNING) == 1


def test_no_warning_without_a_wordlists_file(tmp_path, caplog):
    from app import warn_if_wordlists_present

    with caplog.at_level(logging.WARNING):
        assert not warn_if_wordlists_present([tmp_path / "wordlists.json"])
    assert WARNING not in caplog.text
