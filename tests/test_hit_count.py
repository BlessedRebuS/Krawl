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
