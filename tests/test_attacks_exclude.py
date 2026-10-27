"""The Attacks overlay can hide requests whose IP, path or user agent match a term."""

import sys
import types
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

# routes.* pull in the optional AI client, irrelevant here.
if "aiohttp" not in sys.modules:
    aiohttp_stub = types.ModuleType("aiohttp")
    aiohttp_stub.ClientSession = object
    aiohttp_stub.ClientTimeout = object
    aiohttp_stub.ClientError = Exception
    sys.modules["aiohttp"] = aiohttp_stub

from database import get_database, initialize_database  # noqa: E402
from models import AccessLog, AttackDetection  # noqa: E402

NOW = datetime(2026, 10, 27, 12, 0, 0)


@pytest.fixture
def stored(tmp_path):
    initialize_database(str(tmp_path / "x.db"))
    db = get_database()
    s = db.session
    rows = [
        ("203.0.113.1", "/wp-login.php", "Mozilla/5.0", "login_attempt"),
        ("203.0.113.2", "/xmlrpc.php", "Mozilla/5.0", "wp_xmlrpc_multicall"),
        ("203.0.113.3", "/.env", None, "common_probes"),
        ("198.51.100.9", "/etc/passwd", "sqlmap/1.8", "path_traversal"),
    ]
    for age, (ip, path, ua, attack_type) in enumerate(rows):
        log = AccessLog(
            ip=ip,
            path=path,
            user_agent=ua,
            method="POST",
            is_suspicious=True,
            timestamp=NOW - timedelta(minutes=age),
        )
        s.add(log)
        s.flush()
        s.add(AttackDetection(access_log_id=log.id, attack_type=attack_type))
    s.commit()
    db.close_session()
    return db


def _paths(result):
    return [a["path"] for a in result["attacks"]]


def test_exclude_hides_matching_paths(stored):
    result = stored.analytics.get_attack_types_paginated(
        page_size=10, exclude=["wp-login", "XMLRPC"]
    )

    assert _paths(result) == ["/.env", "/etc/passwd"]
    assert result["pagination"]["total"] == 2


def test_exclude_matches_ip_and_user_agent_and_keeps_empty_user_agents(stored):
    result = stored.analytics.get_attack_types_paginated(
        page_size=10, exclude=["198.51.100.", "mozilla"]
    )

    assert _paths(result) == ["/.env"]


def test_exclude_combines_with_search(stored):
    result = stored.analytics.get_attack_types_paginated(
        page_size=10, search=".php", exclude=["wp-login"]
    )

    assert _paths(result) == ["/xmlrpc.php"]


@pytest.mark.parametrize(
    "raw, terms",
    [
        ("wp-login, xmlrpc", ["wp-login", "xmlrpc"]),
        (" , wp-login,,", ["wp-login"]),
        ("", []),
        (",".join(f"t{i}" for i in range(30)), [f"t{i}" for i in range(10)]),
    ],
)
def test_exclude_terms_are_parsed(raw, terms):
    from routes.htmx import parse_exclude_terms

    assert parse_exclude_terms(raw) == terms


def test_attacks_route_applies_and_keeps_the_exclude_filter(stored):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from routes import htmx

    app = FastAPI()
    app.state.config = SimpleNamespace(dashboard_secret_path="dash")  # noqa: S106
    app.include_router(htmx.router, prefix="/dash")
    client = TestClient(app)

    html = client.get(
        "/dash/htmx/attacks", params={"page_size": 15, "exclude": "wp-login,xmlrpc"}
    ).text

    assert "/etc/passwd" in html
    assert "/wp-login.php" not in html
    assert "/xmlrpc.php" not in html
    # Paging and sorting links keep the filter.
    assert "exclude=wp-login,xmlrpc" in html
    # One removable pill per term; the term travels in a data attribute.
    assert 'data-term="wp-login"' in html
    assert 'data-term="xmlrpc"' in html
    assert html.count("removeExcludeTerm(this.dataset.term)") == 2


def test_exclude_pill_escapes_the_term(stored):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from routes import htmx

    app = FastAPI()
    app.state.config = SimpleNamespace(dashboard_secret_path="dash")  # noqa: S106
    app.include_router(htmx.router, prefix="/dash")

    html = (
        TestClient(app)
        .get("/dash/htmx/attacks", params={"exclude": '"><script>x</script>'})
        .text
    )

    assert "<script>x</script>" not in html


def test_filter_box_appends_not_terms_on_enter():
    overlay = (
        ROOT / "src/templates/jinja2/dashboard/partials/expand_overlay.html"
    ).read_text()
    js = (ROOT / "src/templates/static/js/dashboard.js").read_text()

    # No separate Exclude box: the main filter has a Not toggle.
    assert "expandOverlay.exclude" not in overlay
    assert "toggleExpandInvert()" in overlay
    assert '@keydown.enter.prevent="addExpandExcludeTerm()"' in overlay
    assert "window.addExpandExcludeTerm" in js
    assert "window.removeExcludeTerm" in js
    assert "params.set('exclude', ov.excludes.join(','))" in js
