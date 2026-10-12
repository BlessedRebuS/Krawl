from datetime import datetime, timedelta
from types import SimpleNamespace

from config import get_config
from database import get_database, initialize_database
from models import AccessLog, AttackDetection, CapturedPayload, RequestAsset
from tasks import pre_retention_cleanup


def test_cleanup_progresses_past_suspicious_batch_and_preserves_evidence(
    tmp_path, monkeypatch
):
    initialize_database(str(tmp_path / "cleanup.db"))
    db = get_database()
    monkeypatch.setattr(get_config(), "tasks_cleanup_batch", 2)
    monkeypatch.setattr(
        pre_retention_cleanup,
        "get_wordlists",
        lambda: SimpleNamespace(
            attack_patterns={"xss_attempt": "<script"},
            suspicious_patterns=["scanner"],
        ),
    )
    session = db.session
    old = datetime.now() - timedelta(days=10000)
    rows = [
        AccessLog(
            ip="203.0.113.7",
            path="/plain",
            user_agent=ua,
            method="POST",
            is_suspicious=True,
            is_honeypot_trigger=False,
            timestamp=old,
            raw_request="POST /plain HTTP/1.1\r\n\r\n<script>alert(1)</script>",
        )
        for ua in [
            "scanner",
            "scanner",
            "Mozilla/5.0",
            "Mozilla/5.0",
            "Mozilla/5.0",
            "Mozilla/5.0",
        ]
    ]
    session.add_all(rows)
    session.flush()
    ids = [row.id for row in rows]
    session.add(AttackDetection(access_log_id=ids[3], attack_type="xss_attempt"))
    session.add(
        CapturedPayload(
            access_log_id=ids[4], ip="203.0.113.7", filename="evidence.php", size=10
        )
    )
    session.add(
        RequestAsset(access_log_id=ids[5], url="https://evidence.example/payload")
    )
    session.commit()
    db.close_session()

    pre_retention_cleanup.main()

    states = dict(db.session.query(AccessLog.id, AccessLog.is_suspicious).all())
    assert [states[row_id] for row_id in ids] == [
        True,
        True,
        False,
        True,
        True,
        True,
    ]
