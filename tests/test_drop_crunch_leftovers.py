"""Crunched rows go, their requests stay counted, and the columns drop only later."""

from datetime import datetime, timedelta

from sqlalchemy import inspect, text

from database import get_database, initialize_database
from models import AccessLog, IpStats, MetricsSummary
from tasks import drop_crunch_leftovers as task

IP = "192.0.2.1"


def _old_schema(db):
    now = datetime.now()
    db.session.add(IpStats(ip=IP, total_requests=9, first_seen=now, last_seen=now))
    db.session.add(AccessLog(ip=IP, path="/kept", timestamp=now))
    db.session.commit()
    for sql in (
        "ALTER TABLE access_logs ADD COLUMN hit_count INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE access_logs ADD COLUMN path_samples VARCHAR(2048)",
        "ALTER TABLE ip_stats ADD COLUMN crunched_at TIMESTAMP",
        "INSERT INTO access_logs (ip, path, method, is_suspicious, is_honeypot_trigger,"
        " timestamp, request_metadata_extracted, request_metadata_version,"
        " file_extraction_version, is_interesting, hit_count) VALUES (:ip, '/{link}',"
        " 'GET', 0, 0, :now, 1, 2, 1, 1, 8)",
    ):
        db.session.execute(text(sql), {"ip": IP, "now": now} if ":ip" in sql else {})
    db.session.commit()
    db.close_session()


def test_deletes_rows_then_drops_columns_after_the_delay(tmp_path):
    initialize_database(str(tmp_path / "x.db"))
    db = get_database()
    _old_schema(db)

    task.main()
    assert [r.path for r in db.session.query(AccessLog).all()] == ["/kept"]
    stats = db.session.query(IpStats).one()
    assert (stats.pruned_requests, stats.pruned_total) == (8, 8)
    db.close_session()
    assert len(task._leftovers(db.engine)) == 3

    task.main()  # inside the delay: old pods may still select the columns
    assert len(task._leftovers(db.engine)) == 3

    marker = db.session.get(MetricsSummary, task._MARKER)
    marker.updated_at = datetime.now() - task.DROP_DELAY - timedelta(minutes=1)
    db.session.commit()
    db.close_session()

    task.main()
    assert task._leftovers(db.engine) == []
    assert "hit_count" not in {
        c["name"] for c in inspect(db.engine).get_columns("access_logs")
    }
    assert db.session.get(MetricsSummary, task._MARKER) is None
    assert db.session.query(IpStats).one().pruned_total == 8
    db.close_session()

    task.main()  # already done: a no-op on every later run


def test_fresh_install_has_nothing_to_do(tmp_path):
    initialize_database(str(tmp_path / "fresh.db"))
    db = get_database()
    task.main()
    assert db.session.query(MetricsSummary).count() == 0
    db.close_session()
