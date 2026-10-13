"""A crunched IP must score exactly like the same traffic uncrunched."""

from datetime import datetime, timedelta

from database import get_database, initialize_database
from models import AccessLog, IpStats
from tasks import analyze_ips

UA = "Mozilla/5.0"


def _ip(session, ip, when):
    session.add(
        IpStats(
            ip=ip,
            total_requests=110,
            first_seen=when,
            last_seen=when,
            last_analysis=None,
            need_reevaluation=True,
        )
    )


def test_crunched_ip_scores_like_uncrunched(tmp_path):
    initialize_database(str(tmp_path / "an.db"))
    db = get_database()
    s = db.session
    base = datetime.now() - timedelta(days=8)

    _ip(s, "192.0.2.10", base)
    for i in range(100):
        s.add(
            AccessLog(
                ip="192.0.2.10",
                path=f"/Gw2JM9{i:02d}",
                method="GET",
                user_agent=UA,
                timestamp=base + timedelta(seconds=i),
            )
        )
    _ip(s, "192.0.2.11", base)
    s.add(
        AccessLog(
            ip="192.0.2.11",
            path="/{link}",
            method="GET",
            user_agent=UA,
            timestamp=base + timedelta(seconds=99),
            hit_count=100,
        )
    )
    for ip in ("192.0.2.10", "192.0.2.11"):
        for i in range(10):
            s.add(
                AccessLog(
                    ip=ip,
                    path="/form",
                    method="POST",
                    user_agent=UA,
                    timestamp=base + timedelta(seconds=200 + i),
                )
            )
    s.commit()
    db.close_session()

    analyze_ips.main()

    rows = {r.ip: r for r in db.session.query(IpStats).all()}
    plain, crunched = rows["192.0.2.10"], rows["192.0.2.11"]
    assert crunched.category == plain.category == "good_crawler"
    assert crunched.category_scores == plain.category_scores
    assert (
        crunched.analyzed_metrics["risky_http_methods"]
        == plain.analyzed_metrics["risky_http_methods"]
    )
