from datetime import datetime, timedelta

from database import get_database, initialize_database
from models import AccessLog, AttackDetection, IpStats


def _seed(db):
    now = datetime.now()
    db.session.add_all(
        [
            AccessLog(ip="192.0.2.1", path="/a", user_agent="ua-a", timestamp=now),
            AccessLog(ip="192.0.2.1", path="/a", user_agent="ua-b", timestamp=now),
            AccessLog(ip="192.0.2.2", path="/a", user_agent="ua-b", timestamp=now),
            AccessLog(ip="192.0.2.2", path="/{x}", user_agent="ua-b", timestamp=now),
        ]
    )
    db.session.commit()
    db.close_session()


def test_top_lists_count_rows(tmp_path):
    initialize_database(str(tmp_path / "hits.db"))
    db = get_database()
    _seed(db)

    assert db.analytics.get_top_paths(limit=10) == [("/a", 3), ("/{x}", 1)]
    page = db.analytics.get_top_paths_paginated(page=1, page_size=10, min_count=2)
    assert [(p["path"], p["count"]) for p in page["paths"]] == [("/a", 3)]
    assert db.analytics.get_top_user_agents(limit=10) == [("ua-b", 3), ("ua-a", 1)]


def test_access_table_shows_the_path_and_method():
    from dependencies import get_templates

    env = get_templates().env  # the app's env, with every custom filter registered
    html = env.get_template("dashboard/partials/access_by_ip_table.html").render(
        dashboard_path="/d",
        items=[
            {
                "id": 1,
                "ip": "192.0.2.50",
                "path": "/login",
                "user_agent": "ua",
                "method": "GET",
                "is_suspicious": False,
                "is_honeypot_trigger": False,
                "timestamp": "2026-10-01T00:00:00",
                "attack_types": [],
            }
        ],
        pagination={"page": 1, "page_size": 25, "total": 1, "total_pages": 1},
        sort_by="timestamp",
        sort_order="desc",
        ip_filter="192.0.2.50",
    )
    assert '<span class="path-truncated">/login</span>' in html
    assert "access-row-normal" in html
    assert "<th>Method</th>" in html
    assert '<span class="method-badge method-get">GET</span>' in html


def test_export_honours_ban_overrides(tmp_path):
    initialize_database(str(tmp_path / "export.db"))
    db = get_database()
    now = datetime.now()
    for ip, category, override in (
        ("192.0.2.1", "attacker", None),
        ("192.0.2.2", "attacker", True),
        ("192.0.2.3", "attacker", False),
        ("192.0.2.4", "good_crawler", True),
        ("192.0.2.5", "good_crawler", None),
    ):
        db.session.add(
            IpStats(
                ip=ip,
                total_requests=1,
                first_seen=now,
                last_seen=now,
                category=category,
                ban_override=override,
            )
        )
    db.session.commit()
    db.close_session()

    assert sorted(db.ip_stats.get_ips_for_export(["attacker"])) == [
        "192.0.2.1",
        "192.0.2.2",
        "192.0.2.4",
    ]


def test_request_search_narrows_by_ip_and_host(tmp_path):
    initialize_database(str(tmp_path / "search.db"))
    db = get_database()
    now = datetime.now()
    for ip, host in (
        ("45.1.2.3", "gitea.example"),
        ("145.1.2.3", "demo.example"),
        ("45.1.2.30", "demo.example"),
    ):
        db.session.add(AccessLog(ip=ip, path="/", target_host=host, timestamp=now))
    db.session.commit()
    db.close_session()

    def ips(**filters):
        result = db.access_logs.search_requests(**filters)
        assert result["pagination"]["total"] == len(result["requests"])
        return sorted(r["ip"] for r in result["requests"])

    assert ips(ip="45.1.2.3") == ["45.1.2.3"]  # a full IP is exact
    assert ips(ip="45.1.2") == ["145.1.2.3", "45.1.2.3", "45.1.2.30"]
    assert ips(host="GITEA") == ["45.1.2.3"]
    assert ips(host="nope") == []
    assert ips(host="demo", ip="45.1") == ["145.1.2.3", "45.1.2.30"]


def test_sorted_pages_keep_their_order(tmp_path):

    initialize_database(str(tmp_path / "walk.db"))
    db = get_database()
    base = datetime(2026, 11, 1)
    for i in range(3):
        log = AccessLog(
            ip="192.0.2.1",
            path=f"/p{i}",
            timestamp=base + timedelta(hours=i),
            is_suspicious=True,
        )
        log.attack_detections.append(AttackDetection(attack_type="sqli"))
        db.session.add(log)
    db.session.commit()
    db.close_session()

    def pages():
        searched = db.access_logs.search_requests(path="/p", page_size=2)
        attacks = db.analytics.get_attack_types_paginated(page_size=2, search="/p")
        return [r["path"] for r in searched["requests"]], [
            a["path"] for a in attacks["attacks"]
        ]

    assert pages() == (["/p2", "/p1"], ["/p2", "/p1"])
