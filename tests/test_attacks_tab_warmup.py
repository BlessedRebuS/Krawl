"""The warmup fills the exact cache keys the Attacks tab's default 7D view reads."""

import sys
import types
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

if "aiohttp" not in sys.modules:
    aiohttp_stub = types.ModuleType("aiohttp")
    aiohttp_stub.ClientSession = object
    aiohttp_stub.ClientTimeout = object
    aiohttp_stub.ClientError = Exception
    sys.modules["aiohttp"] = aiohttp_stub

import dashboard_cache  # noqa: E402
from database import get_database, initialize_database  # noqa: E402
from models import AccessLog, AttackDetection  # noqa: E402
from tasks import dashboard_warmup  # noqa: E402


class FakeRedis:
    def __init__(self):
        self.store = {}

    def get(self, k):
        return self.store.get(k)

    def setex(self, k, ttl, v):
        self.store[k] = v

    def exists(self, k):
        return int(k in self.store)


@pytest.fixture
def warmed(tmp_path, monkeypatch):
    initialize_database(str(tmp_path / "x.db"))
    db = get_database()
    s = db.session
    now = datetime.utcnow()
    for i, (ip, path, atype) in enumerate(
        [
            ("203.0.113.1", "/wp-login.php", "login_attempt"),
            ("203.0.113.2", "/.env", "common_probes"),
        ]
    ):
        log = AccessLog(
            ip=ip,
            path=path,
            method="GET",
            is_suspicious=True,
            target_host="victim.test",
            timestamp=now - timedelta(hours=i + 1),
        )
        s.add(log)
        s.flush()
        s.add(AttackDetection(access_log_id=log.id, attack_type=atype))
    s.commit()
    db.close_session()

    monkeypatch.setattr(dashboard_cache, "_backend", "scalable")
    monkeypatch.setattr(dashboard_cache, "_redis_client", FakeRedis())

    monkeypatch.setattr(
        dashboard_warmup,
        "get_config",
        lambda: SimpleNamespace(
            dashboard_cache_warmup=True,
            dashboard_warmup_pages=1,
            dashboard_warmup_aggregation=False,
            dashboard_top_n_min_count=1,
        ),
    )
    dashboard_warmup.main()
    return db


def test_default_7d_panels_are_served_from_the_warmup(warmed, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from routes import htmx

    def boom(*a, **k):
        raise AssertionError("queried the database despite the warm cache")

    monkeypatch.setattr(warmed.analytics, "get_attack_types_paginated", boom)
    monkeypatch.setattr(warmed.analytics, "get_attackers_in_period", boom)
    monkeypatch.setattr(warmed.analytics, "get_attack_facets", boom)
    monkeypatch.setattr(warmed.access_logs, "_domain_rollup_between", boom)

    app = FastAPI()
    app.state.config = SimpleNamespace(dashboard_secret_path="dash")  # noqa: S106
    app.include_router(htmx.router, prefix="/dash")
    client = TestClient(app)
    q = {"page": 1, "days": 7, "offset_days": 0}

    attacks = client.get("/dash/htmx/attacks", params=q)
    assert attacks.status_code == 200 and "/wp-login.php" in attacks.text
    attackers = client.get("/dash/htmx/attackers", params=q)
    assert attackers.status_code == 200 and "203.0.113.2" in attackers.text
    assert ">Detections</th>" in attackers.text  # counts detections, not requests
    assert "detections in the period" in attacks.text
    domains = client.get("/dash/htmx/targeted-domains", params=q)
    assert domains.status_code == 200 and "victim.test" in domains.text


def test_later_pages_reuse_the_warm_total(warmed, monkeypatch):
    from routes import htmx

    seen = {}
    real = warmed.analytics.get_attack_types_paginated

    def spy(**kw):
        seen["total"] = kw["total"]
        return real(**kw)

    monkeypatch.setattr(warmed.analytics, "get_attack_types_paginated", spy)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.state.config = SimpleNamespace(dashboard_secret_path="dash")  # noqa: S106
    app.include_router(htmx.router, prefix="/dash")
    TestClient(app).get(
        "/dash/htmx/attacks", params={"page": 2, "days": 7, "offset_days": 0}
    )
    assert seen["total"] == 2


def test_credentials_panel_narrows_by_ip_and_keeps_it_in_links(warmed):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from models import CredentialAttempt
    from routes import htmx

    s = warmed.session
    now = datetime.utcnow()
    for ip in ("203.0.113.1", "203.0.113.2"):
        s.add(
            CredentialAttempt(ip=ip, path="/login", username=f"u-{ip}", timestamp=now)
        )
    s.commit()
    warmed.close_session()

    app = FastAPI()
    app.state.config = SimpleNamespace(dashboard_secret_path="dash")  # noqa: S106
    app.include_router(htmx.router, prefix="/dash")
    q = {"page": 1, "days": 7, "offset_days": 0, "ip_filter": "203.0.113.2"}
    html = TestClient(app).get("/dash/htmx/credentials", params=q).text
    assert "u-203.0.113.2" in html and "u-203.0.113.1" not in html
    assert "ip_filter=203.0.113.2&amp;days=7" in html
