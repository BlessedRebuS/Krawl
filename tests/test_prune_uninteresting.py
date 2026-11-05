"""Random-path GETs are marked at write time and pruned after a window."""

import pytest
from sqlalchemy import create_engine, inspect, text

import generative_ai
from config import get_config
from database import core, get_database, initialize_database
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
