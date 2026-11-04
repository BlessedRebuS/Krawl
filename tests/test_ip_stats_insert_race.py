import database.core as core
from database import get_database, initialize_database
from models import IpStats


def test_new_ip_insert_survives_concurrent_insert(tmp_path, monkeypatch):
    initialize_database(str(tmp_path / "race.db"))
    db = get_database()
    real = core._insert_ip_stats_if_missing
    created = []

    def racing(session, ip, now):
        real(session, ip, now)  # another replica wins the insert first
        created.append(real(session, ip, now))
        return created[-1]

    monkeypatch.setattr(core, "_insert_ip_stats_if_missing", racing)
    assert db.increment_page_visit("203.0.113.9", 0) == 1
    db.persist_access("203.0.113.10", "/", is_suspicious=True)
    assert created == [False, False]

    rows = {r.ip: r for r in db.session.query(IpStats).all()}
    assert rows["203.0.113.9"].page_visit_count == 1
    assert rows["203.0.113.10"].total_requests == 1
    assert rows["203.0.113.10"].need_reevaluation is True
