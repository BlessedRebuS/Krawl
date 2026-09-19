import pytest

import ban_cache
from database import get_database, initialize_database
from models import IpStats


@pytest.mark.parametrize("limit", [0, -1, 1, 2])
def test_page_visit_threshold_matches_combined_ingest(tmp_path, monkeypatch, limit):
    initialize_database(str(tmp_path / "visits.db"))
    db = get_database()
    monkeypatch.setattr(ban_cache, "_banned", set())
    for count in (1, 2):
        assert db.increment_page_visit("203.0.113.7", limit) == count
        assert (
            db.persist_access(
                "203.0.113.8", "/page", increment_page_visit=True, max_pages_limit=limit
            )
            == count
        )
        rows = db.session.query(IpStats).order_by(IpStats.ip).all()
        assert len(rows) == 2
        for row in rows:
            assert row.page_visit_count == count
            assert (row.ban_timestamp is not None) == (limit > 0 and count >= limit)
            assert ban_cache.is_banned(row.ip) == (limit > 0 and count >= limit)
        db.close_session()
