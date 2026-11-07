"""The map pages geolocated IPs by cursor: every one once, in order, ties included."""

from datetime import datetime, timedelta

from database import get_database, initialize_database
from models import IpStats

BASE = datetime(2026, 11, 1)


def _seed(db):
    for i in range(23):
        db.session.add(
            IpStats(
                ip=f"192.0.2.{i}",
                total_requests=i % 4,  # ties on the sort column
                first_seen=BASE,
                last_seen=BASE + timedelta(minutes=i % 5),
                category="attacker",
                latitude=1.0 if i % 3 else None,  # every third has no location
                longitude=2.0,
            )
        )
    db.session.commit()
    db.close_session()


def _walk(db, sort_by):
    seen, cursor = [], None
    while True:
        page = db.ip_stats.get_all_ips_paginated(
            page_size=4, sort_by=sort_by, cursor=cursor, geolocated=True
        )
        seen += [(ip[sort_by], ip["ip"]) for ip in page["ips"]]
        cursor = page["next_cursor"]
        if not cursor:
            return seen


def test_cursor_pages_cover_every_geolocated_ip_once(tmp_path):
    initialize_database(str(tmp_path / "map.db"))
    db = get_database()
    _seed(db)
    located = {f"192.0.2.{i}" for i in range(23) if i % 3}
    for sort_by in ("total_requests", "last_seen"):
        seen = _walk(db, sort_by)
        assert [ip for _, ip in seen] == [ip for _, ip in sorted(seen, reverse=True)]
        assert sorted(ip for _, ip in seen) == sorted(located)
    first = db.ip_stats.get_all_ips_paginated(page_size=4, geolocated=True)
    assert first["pagination"]["total"] == len(located)


def test_user_agent_pages_sort_and_search(tmp_path):
    from models import AccessLog

    initialize_database(str(tmp_path / "ua.db"))
    db = get_database()
    for ua, n in (("curl/8", 3), ("Mozilla/5.0", 2), ("zgrab", 1)):
        for _ in range(n):
            db.session.add(AccessLog(ip="192.0.2.1", path="/", user_agent=ua))
    db.session.commit()
    db.close_session()

    def uas(**kw):
        page = db.analytics.get_top_user_agents_paginated(page_size=10, **kw)
        return [(u["user_agent"], u["count"]) for u in page["user_agents"]]

    assert uas() == [("curl/8", 3), ("Mozilla/5.0", 2), ("zgrab", 1)]
    assert uas(sort_by="user_agent", sort_order="asc")[0] == ("Mozilla/5.0", 2)
    assert uas(search="MOZ") == [("Mozilla/5.0", 2)]
    assert uas(min_count=2) == [("curl/8", 3), ("Mozilla/5.0", 2)]


def test_cursor_pages_skip_the_table_cache(monkeypatch):
    """A full map load must not land ~2MB per page in Redis."""
    import asyncio

    from routes import api

    stored = []
    fake_db = type("D", (), {})()
    fake_db.ip_stats = type(
        "S", (), {"get_all_ips_paginated": staticmethod(lambda **kw: {"ips": []})}
    )()
    monkeypatch.setattr(api, "get_db", lambda: fake_db)
    monkeypatch.setattr(api, "get_cached_table", lambda key: None)
    monkeypatch.setattr(api, "set_cached_table", lambda key, value: stored.append(key))

    def call(cursor):
        asyncio.run(
            api.all_ips(
                None,
                page=1,
                page_size=5000,
                sort_by="last_seen",
                sort_order="desc",
                cursor=cursor,
                geolocated=True,
            )
        )

    call("")
    call("2026-11-06T11:40:22|1.2.3.4")
    assert len(stored) == 1 and "desc::True" in stored[0]
