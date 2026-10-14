from datetime import datetime, timedelta

from config import get_config
from database import get_database, initialize_database
from models import AccessLog, IpStats
from tasks import db_retention


def test_db_retention_uses_non_suspicious_window(tmp_path, monkeypatch):
    initialize_database(str(tmp_path / "wiring.db"))
    db = get_database()
    monkeypatch.setattr(get_config(), "retention_non_suspicious", timedelta(days=7))
    now = datetime.now()
    db.session.add_all(
        [
            AccessLog(ip="198.51.100.1", path="/old", timestamp=now - timedelta(days=8)),
            AccessLog(ip="198.51.100.1", path="/new", timestamp=now - timedelta(days=6)),
        ]
    )
    db.session.commit()
    db.close_session()

    db_retention.main()

    assert [p for (p,) in db.session.query(AccessLog.path).all()] == ["/new"]


def test_flag_stale_uses_reevaluate_interval(tmp_path, monkeypatch):
    initialize_database(str(tmp_path / "stale.db"))
    db = get_database()
    now = datetime.now()
    db.session.add(
        IpStats(
            ip="198.51.100.2",
            total_requests=1,
            first_seen=now - timedelta(days=10),
            last_seen=now - timedelta(days=1),
            last_analysis=now - timedelta(days=3),
            need_reevaluation=False,
        )
    )
    db.session.commit()
    db.close_session()

    monkeypatch.setattr(get_config(), "retention_reevaluate_interval", timedelta(days=5))
    assert db.ip_stats.flag_stale_ips_for_reevaluation() == 0
    monkeypatch.setattr(get_config(), "retention_reevaluate_interval", timedelta(days=2))
    assert db.ip_stats.flag_stale_ips_for_reevaluation() == 1
