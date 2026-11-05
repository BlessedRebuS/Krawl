"""Random-path GETs are marked at write time and pruned after a window."""

import importlib.util
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine, inspect, text

import generative_ai
from config import get_config
from database import core, get_database, initialize_database
from migrations.runner import run_migrations
from models import AccessLog, IpStats
from tasks import prune_uninteresting

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


@pytest.mark.parametrize(
    "kwargs,expected",
    [
        (dict(path="/Gw2JM958"), True),
        (dict(path="/Gw2JM958", method="POST"), False),
        (dict(path="/Gw2JM958", method="HEAD"), False),
        (dict(path="/test"), False),
        (dict(path="/login"), False),
        (dict(path="/kpjud"), False),
        (dict(path="/a/Gw2JM958"), False),
        (dict(path="/Gw2JM958/"), False),
        (dict(path="/Gw2JM958", is_suspicious=True), False),
        (dict(path="/Gw2JM958", is_honeypot_trigger=True), False),
        (dict(path="/Gw2JM958", attack_types=["sqli"]), False),
        (dict(path="/Gw2JM958", file_payloads=[{"filename": "x"}]), False),
        (dict(path="/Gw2JM958", request_assets=["http://x/y"]), False),
    ],
)
def test_classification(kwargs, expected, monkeypatch):
    monkeypatch.setattr(generative_ai, "load_robots_disallowed", lambda: [])
    args = {
        "method": "GET",
        "is_suspicious": False,
        "is_honeypot_trigger": False,
        "attack_types": None,
        "file_payloads": None,
        "request_assets": None,
        **kwargs,
    }
    assert generative_ai.is_uninteresting_request(**args) is expected


def test_robots_path_is_interesting(monkeypatch):
    monkeypatch.setattr(generative_ai, "load_robots_disallowed", lambda: ["/Gw2JM958"])
    assert not generative_ai.is_uninteresting_request(
        "/Gw2JM958", "GET", False, False, None, None, None
    )


def _marks(session) -> dict:
    session.expire_all()
    return {r.path: r.is_interesting for r in session.query(AccessLog).all()}


def test_persist_marks_row_standalone(tmp_path, monkeypatch):
    monkeypatch.setattr(generative_ai, "load_robots_disallowed", lambda: [])
    initialize_database(str(tmp_path / "t.db"))
    db = get_database()
    db.persist_access(IP, "/Gw2JM958", "UA")
    db.persist_access(IP, "/test", "UA")
    assert _marks(db.session) == {"/Gw2JM958": False, "/test": True}


def test_persist_marks_row_buffered(tmp_path, monkeypatch):
    monkeypatch.setattr(generative_ai, "load_robots_disallowed", lambda: [])
    monkeypatch.setattr(get_config(), "mode", "scalable")
    initialize_database(str(tmp_path / "t.db"))
    core._write_buffer.clear()
    db = get_database()
    db.persist_access(IP, "/Gw2JM958", "UA")
    db.persist_access(IP, "/test", "UA")
    assert db.flush_access_log_buffer() == 2
    assert _marks(db.session) == {"/Gw2JM958": False, "/test": True}


def test_buffered_entry_without_key_is_interesting(tmp_path):
    initialize_database(str(tmp_path / "t.db"))
    core._write_buffer.clear()
    db = get_database()
    core._buffer_access_log_entry(ip=IP, path="/Gw2JM958", user_agent="UA")
    assert db.flush_access_log_buffer() == 1
    assert _marks(db.session) == {"/Gw2JM958": True}


def test_classifier_failure_keeps_request(tmp_path, monkeypatch):
    def boom(*args):
        raise RuntimeError("catalog unavailable")

    monkeypatch.setattr(generative_ai, "is_uninteresting_request", boom, raising=False)
    initialize_database(str(tmp_path / "t.db"))
    db = get_database()
    db.persist_access(IP, "/Gw2JM958", "UA")
    assert _marks(db.session) == {"/Gw2JM958": True}


def _seed(tmp_path, *rows, stats=True, **stats_fields):
    """rows: (path, age_days, is_interesting[, extra AccessLog fields])."""
    initialize_database(str(tmp_path / "t.db"))
    db = get_database()
    if stats:
        db.session.add(IpStats(ip=IP, **stats_fields))
    for path, age, interesting, *extra in rows:
        db.session.add(
            AccessLog(
                ip=IP,
                path=path,
                method="GET",
                user_agent="UA",
                timestamp=datetime.now() - timedelta(days=age),
                is_interesting=interesting,
                **(extra[0] if extra else {}),
            )
        )
    db.session.commit()
    return db


def _paths(db) -> set:
    db.close_session()
    return {r.path for r in db.session.query(AccessLog).all()}


def _stats(db) -> IpStats:
    db.close_session()
    return db.session.get(IpStats, IP)


def test_prunes_only_uninteresting_past_window(tmp_path):
    db = _seed(
        tmp_path,
        ("/Gw2JM958", 8, False),
        ("/Ab3dEf9h", 1, False),
        ("/test", 8, True),
    )
    prune_uninteresting.main()
    assert _paths(db) == {"/Ab3dEf9h", "/test"}
    stats = _stats(db)
    assert stats.pruned_requests == 1
    assert stats.pruned_total == 1
    assert stats.pruned_since is not None


def test_never_prunes_suspicious_or_honeypot(tmp_path):
    db = _seed(
        tmp_path,
        ("/Gw2JM958", 8, False, {"is_suspicious": True}),
        ("/Ab3dEf9h", 8, False, {"is_honeypot_trigger": True}),
    )
    prune_uninteresting.main()
    assert _paths(db) == {"/Gw2JM958", "/Ab3dEf9h"}
    assert _stats(db).pruned_total == 0


def test_counter_adds_within_window(tmp_path):
    since = datetime.now() - timedelta(days=10)
    db = _seed(
        tmp_path,
        ("/Gw2JM958", 8, False),
        ("/Ab3dEf9h", 8, False),
        pruned_requests=5,
        pruned_total=5,
        pruned_since=since,
    )
    prune_uninteresting.main()
    stats = _stats(db)
    assert (stats.pruned_requests, stats.pruned_total) == (7, 7)
    assert stats.pruned_since == since


def test_stale_counter_restarts(tmp_path):
    since = datetime.now() - timedelta(days=31)
    db = _seed(
        tmp_path,
        ("/Gw2JM958", 8, False),
        ("/Ab3dEf9h", 8, False),
        pruned_requests=5,
        pruned_total=5,
        pruned_since=since,
    )
    prune_uninteresting.main()
    stats = _stats(db)
    assert (stats.pruned_requests, stats.pruned_total) == (2, 7)
    assert stats.pruned_since > since


def test_row_without_ip_stats_is_deleted(tmp_path):
    db = _seed(tmp_path, ("/Gw2JM958", 8, False), stats=False)
    prune_uninteresting.main()
    assert _paths(db) == set()


def test_counter_failure_rolls_back_batch(tmp_path, monkeypatch):
    def boom(*args):
        raise RuntimeError("simulated")

    db = _seed(tmp_path, ("/Gw2JM958", 8, False))
    monkeypatch.setattr(prune_uninteresting, "_bump_counters", boom)
    prune_uninteresting.main()
    assert _paths(db) == {"/Gw2JM958"}
    assert _stats(db).pruned_total == 0


def test_deletes_batches_until_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(get_config(), "tasks_retention_delete_batch", 2)
    db = _seed(tmp_path, *[(f"/Gw2JM95{i}", 8, False) for i in range(5)])
    prune_uninteresting.main()
    assert _paths(db) == set()
    assert _stats(db).pruned_requests == 5


def test_uneven_counts_per_ip_are_each_correct(tmp_path):
    db = _seed(tmp_path, ("/Gw2JM958", 8, False), ("/Ab3dEf9h", 8, False))
    other = "192.0.2.61"
    db.session.add(IpStats(ip=other))
    db.session.add(
        AccessLog(
            ip=other,
            path="/Xy7kLm2q",
            method="GET",
            timestamp=datetime.now() - timedelta(days=8),
            is_interesting=False,
        )
    )
    db.session.commit()
    prune_uninteresting.main()
    assert _stats(db).pruned_total == 2
    assert db.session.get(IpStats, other).pruned_total == 1


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/Gw2JM958", True),
        ("/A0ZUzQqbrhyDm", True),
        ("/kpjud", False),
        ("/Rsxmhx", False),
        ("/login", False),
        ("/admin", False),
        ("/dashboard", False),
        ("/Jenkinsfile", False),
        ("/wp-login.php", False),
        ("/.env", False),
        ("/", False),
    ],
)
def test_is_trap_link(path, expected):
    assert generative_ai._is_trap_link(path) is expected


def test_crunch_task_is_gone():
    assert importlib.util.find_spec("tasks.crunch_access_logs") is None


def test_crunch_queue_index_is_dropped_on_sqlite(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE access_logs (id INTEGER PRIMARY KEY, timestamp TIMESTAMP)"
            )
        )
        conn.execute(
            text("CREATE TABLE ip_stats (ip TEXT PRIMARY KEY, last_seen TEXT)")
        )
        conn.execute(
            text("CREATE INDEX ix_ip_stats_crunch_queue ON ip_stats (last_seen)")
        )
    run_migrations(engine)
    names = {i["name"] for i in inspect(engine).get_indexes("ip_stats")}
    assert "ix_ip_stats_crunch_queue" not in names
