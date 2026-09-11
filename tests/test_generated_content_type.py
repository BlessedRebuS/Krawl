#!/usr/bin/env python3

"""
Generated pages answer with the right Content-Type.

A request for /app.js.map used to come back as an HTML corporate landing page:
generate_html_for_path wrapped any non-HTML response in <html><body>, hardcoded
text/html at every return, and the route then discarded the content type by
using HTMLResponse. A scanner that asks for a sourcemap and gets HTML has
learned it is not talking to a real server, which is the one thing a honeypot
cannot afford.

Imports the module by source rather than normally: generative_ai pulls in
aiohttp, which the test environment does not need for this.

Usage: python tests/test_generated_content_type.py
"""

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))


def _content_type_for_path():
    source = (SRC / "generative_ai.py").read_text(encoding="utf-8")
    start = source.index("_CONTENT_TYPES = {")
    end = source.index("async def generate_html_for_path(")
    namespace: dict = {}
    exec(source[start:end], namespace)  # noqa: S102 — the module under test
    return namespace["content_type_for_path"]


def test_data_paths_are_not_html():
    """The reported case, plus the file types a scanner probes for."""
    ct = _content_type_for_path()
    expected = {
        "/app.js.map": "application/json",
        "/api/users.json": "application/json",
        "/.env": "text/plain",
        "/backup.sql": "text/plain",
        "/wp-config.php.bak": "text/plain",
        "/config.php": "text/plain",
        "/robots.txt": "text/plain",
        "/data.xml": "application/xml",
        "/report.csv": "text/csv",
        "/style.css": "text/css",
    }
    for path, want in expected.items():
        got = ct(path)
        assert got == want, f"{path}: expected {want}, got {got}"
    print("OK: data and config paths get their real content type")


def test_pages_stay_html():
    """Anything without a data extension is still a page."""
    ct = _content_type_for_path()
    for path in ("/", "/admin", "/some/dir/", "/index.html", "/a.unknownext"):
        assert ct(path) == "text/html", path
    print("OK: page paths stay text/html")


def test_wrapping_is_limited_to_html():
    """The <html><body> wrap must be guarded by the content type.

    Checked against the source because exercising the real call needs a
    provider; the guard is the line that broke, so it is the line to pin.
    """
    source = (SRC / "generative_ai.py").read_text(encoding="utf-8")
    assert 'if content_type == "text/html" and not html_content.startswith("<")' in source, (
        "the wrap is no longer guarded by content type — a JSON response "
        "would be wrapped in HTML again"
    )
    print("OK: only text/html responses get wrapped")


def test_route_sends_the_content_type():
    """honeypot.py must not go back to HTMLResponse, which hardcodes the type."""
    source = (SRC / "routes" / "honeypot.py").read_text(encoding="utf-8")
    marker = "media_type=content_type,"
    assert marker in source, "the AI route is not passing the generated content type"
    print("OK: the route sends the generated content type")


if __name__ == "__main__":
    test_data_paths_are_not_html()
    test_pages_stay_html()
    test_wrapping_is_limited_to_html()
    test_route_sends_the_content_type()
