"""Top paths leaves out crunch templates but keeps literal merges and real paths."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from database import get_database, initialize_database  # noqa: E402
from models import AccessLog  # noqa: E402


def test_top_paths_skip_crunch_templates(tmp_path):
    initialize_database(str(tmp_path / "x.db"))
    db = get_database()
    for path, hits in (
        ("/{link}", 50),  # crunched trap links
        ("/wp-login.php", 3),  # crunched literal repeats
        ("/${jndi:ldap://x}", 1),  # real path, never crunched
        ("/${jndi:ldap://x}", 1),
    ):
        db.session.add(AccessLog(ip="203.0.113.1", path=path, hit_count=hits))
    db.session.commit()
    db.close_session()

    expected = [("/wp-login.php", 3), ("/${jndi:ldap://x}", 2)]
    assert db.analytics.get_top_paths(limit=10) == expected
    page = db.analytics.get_top_paths_paginated(page_size=10)
    assert [(p["path"], p["count"]) for p in page["paths"]] == expected
