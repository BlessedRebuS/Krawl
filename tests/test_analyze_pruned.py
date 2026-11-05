"""An IP must score the same whether its random-path GETs were pruned or not."""

from collections import Counter
from datetime import datetime, timedelta

import pytest

from config import get_config, pruned_window
from database import get_database, initialize_database
from database.ip_stats import pruned_estimate
from models import AccessLog, IpStats
from tasks import analyze_ips, prune_uninteresting

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


def _log(session, ip, path, method="GET", ua=UA, age_days=8):
    session.add(
        AccessLog(
            ip=ip,
            path=path,
            method=method,
            user_agent=ua,
            timestamp=datetime.now() - timedelta(days=age_days),
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
        pruned_since=datetime.now() - timedelta(days=47),
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


def test_counter_rollover_keeps_steady_crawler_category(tmp_path):
    # 100 trap GETs and 5 POSTs a day: 7 days of GET rows, 30 of POST rows, and a
    # counter that rolled over a moment ago, holding 23 days of pruned GETs.
    initialize_database(str(tmp_path / "a.db"))
    db = get_database()
    ip = "192.0.2.16"
    _ip(
        db.session,
        ip,
        pruned_requests=100,
        pruned_previous=2300,
        pruned_since=datetime.now(),
    )
    for day in range(1, 8):
        for i in range(100):
            _log(db.session, ip, f"/Gw2JM{day}{i:02d}", age_days=day)
    for day in range(1, 31):
        for i in range(5):
            _log(db.session, ip, f"/form{day}{i}", method="POST", age_days=day)
    db.session.commit()

    analyze_ips.main()

    stats = _analyzed(db, ip)
    assert stats.category == "good_crawler"
    assert stats.analyzed_metrics["risky_http_methods"] < 0.1


def test_steady_ip_estimate_holds_across_rollovers(tmp_path):
    # Real counter writes, 100 pruned a day for 120 days: the estimate must keep
    # about one window's worth, never dropping back near a single day's count.
    initialize_database(str(tmp_path / "a.db"))
    db = get_database()
    ip = "192.0.2.17"
    _ip(db.session, ip)
    db.session.commit()
    window = pruned_window(get_config())
    start = datetime.now()
    expected = 100 * window.days
    for day in range(120):
        now = start + timedelta(days=day)
        prune_uninteresting._bump_counters(db.session, Counter({ip: 100}), now)
        db.session.commit()
        db.session.expire_all()
        row = db.session.get(IpStats, ip)
        estimate = pruned_estimate(
            row.pruned_requests,
            row.pruned_previous,
            row.pruned_since,
            now + timedelta(hours=12),
            window,
        )
        if day >= window.days:
            assert 0.9 * expected <= estimate <= 1.1 * expected, day
        else:
            assert estimate <= 100 * (day + 1)
    assert db.session.get(IpStats, ip).pruned_total == 12000


@pytest.mark.parametrize(
    "current,previous,age_days,expected",
    [
        (100, 0, 0, 100),  # fresh counter
        (100, 230, 0, 330),  # previous period counts in full right after rollover
        (100, 230, 11.5, 215),  # half of the previous period has left the window
        (100, 230, 23, 100),  # the previous period is gone; current is all that's left
        (100, 230, 34.5, 50),  # idle: current is now the older period
        (100, 230, 46, 0),  # idle for two periods: nothing is left
        (5000, 0, 60, 0),  # months-old GETs never hide a new attack
    ],
)
def test_pruned_estimate(current, previous, age_days, expected):
    now = datetime.now()
    since = now - timedelta(days=age_days)
    window = timedelta(days=23)
    assert pruned_estimate(current, previous, since, now, window) == expected


def test_pruned_estimate_without_counter():
    assert pruned_estimate(0, 0, None, datetime.now(), timedelta(days=23)) == 0


def test_window_never_collapses():
    cfg = get_config()
    assert pruned_window(cfg) == timedelta(days=30) - cfg.retention_uninteresting
    long_retention = type("C", (), {"retention_uninteresting": timedelta(days=90)})
    assert pruned_window(long_retention) == timedelta(days=1)


def test_analyzer_stores_timing_for_the_hexagon(tmp_path):
    initialize_database(str(tmp_path / "a.db"))
    db = get_database()
    ip = "192.0.2.18"
    _ip(db.session, ip)
    for gap in (0, 1, 40, 41, 200):
        db.session.add(
            AccessLog(
                ip=ip,
                path="/test",
                method="GET",
                user_agent=UA,
                timestamp=datetime.now() - timedelta(seconds=gap),
            )
        )
    db.session.commit()

    analyze_ips.main()

    assert _analyzed(db, ip).analyzed_metrics["request_timing_cv"] > 0
