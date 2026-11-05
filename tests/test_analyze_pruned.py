"""An IP must score the same whether its random-path GETs were pruned or not."""

from datetime import datetime, timedelta

from database import get_database, initialize_database
from models import AccessLog, IpStats
from tasks import analyze_ips

UA = "Mozilla/5.0"


def _ip(session, ip, **fields):
    now = datetime.now()
    session.add(
        IpStats(
            ip=ip,
            total_requests=110,
            first_seen=now,
            last_seen=now,
            last_analysis=None,
            need_reevaluation=True,
            **fields,
        )
    )


def _log(session, ip, path, method="GET", ua=UA):
    session.add(
        AccessLog(
            ip=ip,
            path=path,
            method=method,
            user_agent=ua,
            timestamp=datetime.now() - timedelta(days=8),
        )
    )


def _analyzed(db, ip) -> IpStats:
    db.close_session()
    return db.session.get(IpStats, ip)


def test_pruned_ip_scores_like_unpruned(tmp_path):
    initialize_database(str(tmp_path / "a.db"))
    db = get_database()
    s = db.session
    plain, pruned = "192.0.2.10", "192.0.2.11"
    _ip(s, plain)
    for i in range(100):
        _log(s, plain, f"/Gw2JM9{i:02d}")
    _ip(s, pruned, pruned_requests=100, pruned_since=datetime.now())
    for ip in (plain, pruned):
        for i in range(5):
            _log(s, ip, f"/form{i}", method="POST")
    s.commit()

    analyze_ips.main()

    a, b = _analyzed(db, plain), db.session.get(IpStats, pruned)
    assert a.category == b.category
    assert a.category_scores == b.category_scores
    assert (
        a.analyzed_metrics["risky_http_methods"]
        == b.analyzed_metrics["risky_http_methods"]
    )
    assert b.analyzed_metrics["risky_http_methods"] < 0.1


def test_stale_counter_is_ignored(tmp_path):
    initialize_database(str(tmp_path / "a.db"))
    db = get_database()
    ip = "192.0.2.12"
    _ip(
        db.session,
        ip,
        pruned_requests=5000,
        pruned_since=datetime.now() - timedelta(days=31),
    )
    for i in range(100):
        _log(db.session, ip, f"/form{i}", method="POST")
    db.session.commit()

    analyze_ips.main()

    assert _analyzed(db, ip).analyzed_metrics["risky_http_methods"] == 1.0


def test_user_agents_survive_pruning(tmp_path):
    initialize_database(str(tmp_path / "a.db"))
    db = get_database()
    ip = "192.0.2.13"
    _ip(
        db.session,
        ip,
        pruned_requests=10,
        pruned_since=datetime.now(),
        analyzed_metrics={"different_user_agents": ["A", "B"]},
    )
    _log(db.session, ip, "/test", ua="B")
    db.session.commit()

    analyze_ips.main()

    used = _analyzed(db, ip).analyzed_metrics["different_user_agents"]
    assert sorted(used) == ["A", "B"]


def test_user_agents_not_merged_without_pruning(tmp_path):
    initialize_database(str(tmp_path / "a.db"))
    db = get_database()
    ip = "192.0.2.14"
    _ip(db.session, ip, analyzed_metrics={"different_user_agents": ["A", "B"]})
    _log(db.session, ip, "/test", ua="B")
    db.session.commit()

    analyze_ips.main()

    assert _analyzed(db, ip).analyzed_metrics["different_user_agents"] == ["B"]


def test_counter_without_rows_marks_analysed(tmp_path):
    initialize_database(str(tmp_path / "a.db"))
    db = get_database()
    ip = "192.0.2.15"
    _ip(db.session, ip, pruned_requests=10, pruned_since=datetime.now())
    db.session.commit()

    analyze_ips.main()

    assert not _analyzed(db, ip).need_reevaluation
