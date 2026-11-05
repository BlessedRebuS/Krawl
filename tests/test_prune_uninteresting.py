"""Random-path GETs are marked at write time and pruned after a window."""

from sqlalchemy import create_engine, inspect, text

from database import get_database, initialize_database
from migrations.runner import run_migrations
from models import AccessLog, IpStats

IP = "192.0.2.60"


def test_new_columns_default_correctly(tmp_path):
    initialize_database(str(tmp_path / "t.db"))
    s = get_database().session
    s.add(AccessLog(ip=IP, path="/x", method="GET"))
    s.add(IpStats(ip=IP))
    s.commit()
    log = s.query(AccessLog).one()
    stats = s.query(IpStats).one()
    assert log.is_interesting is True
    assert stats.pruned_requests == 0
    assert stats.pruned_total == 0
    assert stats.pruned_since is None


def test_migration_adds_columns_to_old_database(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE access_logs (id INTEGER PRIMARY KEY, ip TEXT, "
                "timestamp TIMESTAMP)"
            )
        )
        conn.execute(text("CREATE TABLE ip_stats (ip TEXT PRIMARY KEY)"))
        conn.execute(text("INSERT INTO access_logs (ip) VALUES ('192.0.2.1')"))
        conn.execute(text("INSERT INTO ip_stats (ip) VALUES ('192.0.2.1')"))

    run_migrations(engine)

    with engine.connect() as conn:
        assert conn.execute(text("SELECT is_interesting FROM access_logs")).scalar()
        assert conn.execute(text("SELECT pruned_requests FROM ip_stats")).scalar() == 0
        assert conn.execute(text("SELECT pruned_total FROM ip_stats")).scalar() == 0
    names = {i["name"] for i in inspect(engine).get_indexes("access_logs")}
    assert "ix_access_logs_prunable" in names
