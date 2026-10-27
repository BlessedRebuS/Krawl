"""wordlists.json is gone: no loader, no packaging, one warning for a leftover file."""

import importlib.util
import logging
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WARNING = (
    "wordlists.json is no longer read; move proxy_headers, credential fields and "
    "scoring weights to config.yaml (see docs/honeypot.md)."
)


@pytest.mark.parametrize(
    "module", ["wordlists", "generators", "deception_responses", "fake_responses"]
)
def test_generator_modules_are_gone(module):
    assert importlib.util.find_spec(module) is None


def test_wordlists_file_is_gone():
    assert not (ROOT / "wordlists.json").exists()


def _deployment_files():
    yield ROOT / "Dockerfile"
    yield from ROOT.glob("docker-compose*.yaml")
    yield from (ROOT / "docker").rglob("*.yaml")
    yield from (item for item in (ROOT / "helm").rglob("*") if item.is_file())
    yield from (ROOT / "kubernetes").glob("*.yaml")


@pytest.mark.parametrize(
    "path", sorted(_deployment_files()), ids=lambda p: str(p.relative_to(ROOT))
)
def test_no_deployment_file_mentions_wordlists(path):
    assert "wordlists" not in path.read_text(encoding="utf-8").lower()


def test_html_templates_are_gone():
    assert not (ROOT / "src" / "templates" / "html").exists()


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
