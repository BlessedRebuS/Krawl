#!/usr/bin/env python3

"""Every /htmx/ and /api/ URL the dashboard asks for must have a route.

When one does not, nothing fails loudly: the request falls through to the
honeypot's catch-all, which answers with a generated deception page, and the
panel cheerfully renders "Krawl me!" and a list of random bait links where its
table should be. That is exactly what happened when removing the inline IP
dropdown took two neighbouring routes with it.

Usage: python3 tests/test_dashboard_routes_exist.py
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

REFERENCE = re.compile(r"/(?:htmx|api)/[A-Za-z0-9_{}/.-]+")
# Links out to other people's docs contain paths that look like ours.
ABSOLUTE_URL = re.compile(r"https?://\S+")


def _normalise(path: str) -> str:
    """Drop templated and parameterised segments, keeping the static prefix.

    A template writes `/api/raw-request/{{ log.id }}` and the route declares
    `/api/raw-request/{log_id}`; both reduce to `/api/raw-request`.
    """
    path = path.split("{")[0]
    return path.rstrip("/")


def _referenced() -> set[str]:
    found = set()
    for folder in ("templates/jinja2", "templates/static/js"):
        for f in (ROOT / "src" / folder).rglob("*"):
            if f.is_file() and f.suffix in {".html", ".js"}:
                text = ABSOLUTE_URL.sub("", f.read_text())
                found.update(_normalise(m) for m in REFERENCE.findall(text))
    return {p for p in found if p}


def test_every_referenced_endpoint_is_routed():
    from routes import api, dashboard, htmx

    registered = set()
    for module in (api, htmx, dashboard):
        for route in module.router.routes:
            registered.add(_normalise(route.path))

    missing = sorted(p for p in _referenced() if p not in registered)
    assert not missing, (
        "dashboard asks for unrouted endpoints (the honeypot "
        f"will answer these with a deception page): {missing}"
    )


if __name__ == "__main__":
    test_every_referenced_endpoint_is_routed()
    print(f"ok  every referenced endpoint is routed ({len(_referenced())} checked)")
