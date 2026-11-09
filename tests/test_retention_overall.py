from datetime import datetime, timedelta

from config import get_config
from database import get_database, initialize_database
from models import AccessLog, AttackDetection, CredentialAttempt, IpStats
from tasks import db_retention


def _seed(db):
    now = datetime.now()
    old = now - timedelta(days=400)
    log = AccessLog(ip="203.0.113.9", path="/.env", is_suspicious=True, timestamp=old)
    db.session.add(log)
    db.session.flush()
    db.session.add(AttackDetection(access_log_id=log.id, attack_type="sensitive_file"))
    db.session.add(
        CredentialAttempt(ip="203.0.113.9", path="/login", username="a", password="b", timestamp=old)
    )
    db.session.add(
        IpStats(ip="203.0.113.9", total_requests=1, first_seen=old, last_seen=old, category="attacker")
    )
    db.session.add(AccessLog(ip="203.0.113.10", path="/.git", is_suspicious=True, timestamp=now))
    db.session.commit()
    db.close_session()


def test_overall_null_keeps_old_evidence(tmp_path):
    initialize_database(str(tmp_path / "keep.db"))
    db = get_database()
    _seed(db)
    assert get_config().retention_overall is None

    db_retention.main()

    assert db.session.query(AccessLog).count() == 2
    assert db.session.query(CredentialAttempt).count() == 1
    assert db.session.query(IpStats).count() == 1


def test_overall_set_deletes_everything_older(tmp_path, monkeypatch):
    initialize_database(str(tmp_path / "cap.db"))
    db = get_database()
    _seed(db)
    monkeypatch.setattr(get_config(), "retention_overall", timedelta(days=365))

    db_retention.main()

    assert [p for (p,) in db.session.query(AccessLog.path).all()] == ["/.git"]
    assert db.session.query(AttackDetection).count() == 0
    assert db.session.query(CredentialAttempt).count() == 0
    assert db.session.query(IpStats).count() == 0
