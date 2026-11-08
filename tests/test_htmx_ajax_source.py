"""Every htmx.ajax call names its own source element.

Without `source`, htmx issues every htmx.ajax request from <body> and keeps only
the last queued one, so panels loading together silently lose all but the first
and last request.
"""

import re
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "src" / "templates"


def test_htmx_ajax_calls_pass_a_source():
    missing = []
    for path in [*STATIC.glob("static/js/*.js"), *STATIC.rglob("jinja2/**/*.html")]:
        text = path.read_text()
        for m in re.finditer(r"htmx\.ajax\(", text):
            options = text[m.end() :].split("});", 1)[0]
            if "source" not in options:
                missing.append(f"{path.name}:{text[: m.start()].count(chr(10)) + 1}")
    assert missing == []
