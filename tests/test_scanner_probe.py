"""Catch-all probes must not get AI-generated pages."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
pytest.importorskip("aiohttp")

from generative_ai import _is_scanner_probe  # noqa: E402


@pytest.mark.parametrize(
    "path",
    [
        "/96om2ovp4yvcykxos7y0",
        "/0262a3n164vhrhn7y5li",
        "/zzcanary-12df8f87e32f43fe",
        "/wp-admin/zzcanary-169ca2a5a3c1130f.php",
        "/.git/non_existent_check_998241.txt",
        "/.well-known/agentcensus-control-probe-should-404.json",
        "/nmaplowercheck1778831147",
        "/z9x8c7v6b5-debug-trigger-api.chungo.dev",
        "/0blQnPgX/.git/config",
        "/admin/OsFDKjoK",
        "/zz-nx-audit-chungo.d",
    ],
)
def test_probe(path):
    assert _is_scanner_probe(path)


@pytest.mark.parametrize(
    "path",
    [
        "/administrator",
        "/wp-admin/admin-ajax.php",
        "/.git/objects/0a/e7195354e5379b029129887f9c56802f409359",
        "/@fs/urandom",
        "/phpmyadmin2024",
        "/repo/.git/config",
        "/admin/settings",
        "/Account/Login",
    ],
)
def test_not_probe(path):
    assert not _is_scanner_probe(path)
