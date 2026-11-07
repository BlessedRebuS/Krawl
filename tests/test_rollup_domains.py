import json
from datetime import datetime, timedelta

import dashboard_cache
from database import get_database, initialize_database
from database.access_logs import DOMAIN_DAILY_KEY
from models import AccessLog
from tasks import rollup_domains

NOW = datetime(2026, 11, 4, 12, 0)
WEEK = timedelta(days=7)


class FakeRedis:
    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def set(self, key, value):
        self.store[key] = value

    def setex(self, key, ttl, value):
        self.store[key] = value


def _log(s, ip, host, age, suspicious=False):
    s.add(
        AccessLog(
            ip=ip,
            path="/",
            target_host=host,
            timestamp=NOW - age,
            is_suspicious=suspicious,
        )
    )


def test_day_totals_in_redis_and_retention(tmp_path, monkeypatch):
    initialize_database(str(tmp_path / "rollup.db"))
    db = get_database()
    monkeypatch.setattr(dashboard_cache, "_backend", "scalable")
    monkeypatch.setattr(dashboard_cache, "_redis_client", FakeRedis())
    monkeypatch.setattr(
        rollup_domains, "datetime", type("D", (datetime,), {"now": lambda: NOW})
    )
    monkeypatch.setattr(
        "config.get_config",
        lambda: type("C", (), {"retention_non_suspicious": WEEK}),
    )
    s = db.session
    _log(s, "192.0.2.1", "a.test", timedelta(days=10))
    _log(s, "192.0.2.1", "a.test", timedelta(days=10), suspicious=True)
    _log(s, "192.0.2.2", "a.test", timedelta(days=10))
    for _ in range(4):
        _log(s, "192.0.2.2", "a.test", timedelta(days=1))
    _log(s, "192.0.2.3", "b.test", timedelta(minutes=2))
    s.commit()
    db.close_session()

    def domains():
        return {
            d["domain"]: (d["count"], d["distinct_ips"])
            for d in db.access_logs.get_domain_rollup(refresh=True)
        }

    # Live read, before the task ever ran.
    assert domains() == {"a.test": (7, 2), "b.test": (1, 1)}
    rollup_domains.main()
    # Day 10: .1 has both kinds but counts once; .2 again on day 1: IP-days.
    assert domains() == {"a.test": (7, 3), "b.test": (1, 1)}

    # Retention removed the plain day-10 rows; evidence stays.
    s = db.session
    s.query(AccessLog).filter(
        AccessLog.timestamp < NOW - WEEK, AccessLog.is_suspicious.is_(False)
    ).delete()
    s.commit()
    db.close_session()
    rollup_domains.main()
    assert domains() == {"a.test": (5, 2), "b.test": (1, 1)}
    days = json.loads(dashboard_cache._redis_client.get(DOMAIN_DAILY_KEY))
    assert days[(NOW - timedelta(days=10)).date().isoformat()]["0"] == {}
