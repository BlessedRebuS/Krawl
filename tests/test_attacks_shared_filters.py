"""Search / NOT / method / IP filters narrow every Attacks-tab panel."""

import sys
import types
from datetime import datetime, timedelta
from pathlib import Path

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
from database.text_filters import (  # noqa: E402
    clean_text_filters,
    text_filter_key,
    text_filter_qs,
)
from models import AccessLog, AttackDetection, CredentialAttempt  # noqa: E402

NOW = datetime.utcnow()
SINCE, UNTIL = NOW - timedelta(days=1), NOW + timedelta(minutes=1)

ROWS = [
    # ip, method, path, ua, attack_type, honeypot, host
    ("203.0.113.1", "POST", "/wp-login.php", "Mozilla/5.0", "login_attempt", True, "a.test"),
    ("203.0.113.2", "POST", "/xmlrpc.php", "Mozilla/5.0", "wp_xmlrpc_multicall", True, "b.test"),
    ("198.51.100.9", "GET", "/etc/passwd", "sqlmap/1.8", "path_traversal", True, "c.test"),
]


@pytest.fixture
def db(tmp_path):
    initialize_database(str(tmp_path / "x.db"))
    db = get_database()
    s = db.session
    for age, (ip, method, path, ua, atype, hp, host) in enumerate(ROWS):
        log = AccessLog(
            ip=ip,
            method=method,
            path=path,
            user_agent=ua,
            is_suspicious=True,
            is_honeypot_trigger=hp,
            target_host=host,
            timestamp=NOW - timedelta(minutes=age + 1),
        )
        s.add(log)
        s.flush()
        s.add(AttackDetection(access_log_id=log.id, attack_type=atype))
        s.add(
            CredentialAttempt(
                ip=ip, path=path, username=f"user{age}", timestamp=log.timestamp
            )
        )
    s.commit()
    db.close_session()
    return db


def _ips(rows, key="ip"):
    return sorted(r[key] for r in rows)


def test_attackers_follow_not_search_and_method(db):
    a = db.analytics
    base = dict(since=SINCE, until=UNTIL)
    assert _ips(a.get_attackers_in_period(**base, exclude=["wp-login"])["attackers"]) == [
        "198.51.100.9",
        "203.0.113.2",
    ]
    assert _ips(a.get_attackers_in_period(**base, search="sqlmap")["attackers"]) == [
        "198.51.100.9"
    ]
    assert _ips(a.get_attackers_in_period(**base, method_filter="get")["attackers"]) == [
        "198.51.100.9"
    ]


def test_chart_and_facets_follow_not(db):
    daily = db.analytics.get_attack_types_daily(days=1, exclude=["wp-login"])
    assert {t["type"] for t in daily["attack_types"]} == {
        "wp_xmlrpc_multicall",
        "path_traversal",
    }
    facets = db.analytics.get_attack_facets(SINCE, UNTIL, ip_filter="203.0.113.1")
    assert sum(facets["severities"].values()) == 1


def test_credentials_match_path_and_username(db):
    c = db.credentials
    got = c.get_paginated(page_size=10, since=SINCE, until=UNTIL, exclude=["wp-login"])
    assert _ips(got["credentials"]) == ["198.51.100.9", "203.0.113.2"]
    got = c.get_paginated(page_size=10, since=SINCE, until=UNTIL, search="user2")
    assert _ips(got["credentials"]) == ["198.51.100.9"]


def test_honeypot_and_domains_follow_not(db):
    hp = db.access_logs.get_honeypot_paginated(
        page_size=10, since=SINCE, until=UNTIL, exclude=["xmlrpc"]
    )
    assert _ips(hp["honeypots"]) == ["198.51.100.9", "203.0.113.1"]
    dom = db.access_logs.get_targeted_domains(
        page_size=10, since=SINCE, until=UNTIL, exclude=["passwd"]
    )
    assert sorted(d["domain"] for d in dom["domains"]) == ["a.test", "b.test"]


def test_no_filters_change_nothing(db):
    a = db.analytics
    assert len(a.get_attackers_in_period(since=SINCE, until=UNTIL)["attackers"]) == 3
    assert clean_text_filters("", "", "", "") == {}
    assert text_filter_key({}) == "" and text_filter_qs({}) == ""


def test_filter_helpers_normalise_and_quote():
    tf = clean_text_filters(" a b ", "wp-login, ,x", "get", "")
    assert tf == {"search": "a b", "exclude": "wp-login,x", "method_filter": "GET"}
    assert text_filter_qs(tf) == "&search=a%20b&exclude=wp-login%2Cx&method_filter=GET"


def test_search_terms_stack_and_all_must_match(db):
    a = db.analytics
    base = dict(since=SINCE, until=UNTIL)
    got = a.get_attackers_in_period(**base, search=".php,Mozilla")["attackers"]
    assert _ips(got) == ["203.0.113.1", "203.0.113.2"]
    got = a.get_attackers_in_period(**base, search=["xmlrpc", "Mozilla"])["attackers"]
    assert _ips(got) == ["203.0.113.2"]
    assert clean_text_filters("a, b,,a", "", "", "")["search"] == "a,b,a"
