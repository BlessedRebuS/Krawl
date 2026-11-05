from datetime import datetime

from database import get_database, initialize_database
from models import AccessLog


def _seed(db):
    now = datetime.now()
    db.session.add_all(
        [
            AccessLog(
                ip="192.0.2.1",
                path="/{link}",
                user_agent="ua-a",
                timestamp=now,
                hit_count=5,
                path_samples="/Gw2JM958, /A0ZUzQq",
            ),
            AccessLog(ip="192.0.2.1", path="/a", user_agent="ua-b", timestamp=now),
            AccessLog(ip="192.0.2.2", path="/a", user_agent="ua-b", timestamp=now),
        ]
    )
    db.session.commit()
    db.close_session()


def test_top_paths_sum_hit_count(tmp_path):
    initialize_database(str(tmp_path / "hits.db"))
    db = get_database()
    _seed(db)

    # Crunch templates are left out of top paths (test_top_paths_crunch.py).
    assert db.analytics.get_top_paths(limit=10) == [("/a", 2)]
    page = db.analytics.get_top_paths_paginated(page=1, page_size=10)
    assert [(p["path"], p["count"]) for p in page["paths"]] == [("/a", 2)]
    assert db.analytics.get_top_user_agents(limit=10) == [("ua-a", 5), ("ua-b", 2)]
    page = db.analytics.get_top_paths_paginated(page=1, page_size=10, min_count=2)
    assert [p["path"] for p in page["paths"]] == ["/a"]


def test_log_dicts_carry_hit_count_and_samples(tmp_path):
    initialize_database(str(tmp_path / "dicts.db"))
    db = get_database()
    _seed(db)

    rows = db.access_logs.get_list(ip_filter="192.0.2.1")
    crunched = next(r for r in rows if r["path"] == "/{link}")
    assert crunched["hit_count"] == 5
    assert crunched["path_samples"] == "/Gw2JM958, /A0ZUzQq"
    page = db.access_logs.get_paginated(page=1, page_size=10, ip_filter="192.0.2.1")
    assert {r["hit_count"] for r in page["access_logs"]} == {1, 5}


IP = "192.0.2.50"


def test_access_table_shows_count_and_samples():
    from dependencies import get_templates

    env = get_templates().env  # the app's env, with every custom filter registered
    html = env.get_template("dashboard/partials/access_by_ip_table.html").render(
        dashboard_path="/d",
        items=[
            {
                "id": 1,
                "ip": IP,
                "path": "/{link}",
                "user_agent": "ua",
                "method": "GET",
                "is_suspicious": False,
                "is_honeypot_trigger": False,
                "timestamp": "2026-10-01T00:00:00",
                "attack_types": [],
                "hit_count": 4,
                "path_samples": "/Gw2JM958, /A0ZUzQqbrhyDm",
            }
        ],
        pagination={"page": 1, "page_size": 25, "total": 1, "total_pages": 1},
        sort_by="timestamp",
        sort_order="desc",
        ip_filter=IP,
    )
    assert "/{link} ×4" in html
    assert "access-row-normal" in html  # crunched rows look like normal rows
    assert 'class="path-truncated path-crunched"' in html  # lighter blue path
    assert 'title="/Gw2JM958, /A0ZUzQqbrhyDm"' in html
    assert "Examples" not in html
    assert "<th>Method</th>" in html
    assert '<span class="method-badge method-get">GET</span>' in html


def test_crunched_at_migration_type_is_valid_on_postgres():
    # PostgreSQL has no DATETIME type; the ALTER would fail and every ip_stats
    # query would then hit a missing column on upgraded installs.
    from migrations.runner import COLUMNS

    types = {(t, c): ty for t, c, ty in COLUMNS}
    assert types[("ip_stats", "crunched_at")] == "TIMESTAMP"
