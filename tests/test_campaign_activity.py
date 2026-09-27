"""Threats tab: campaign activity is windowed, and artifact tables filter by
how many IPs share a value."""

import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import database as dbpkg  # noqa: E402


def _db(tmp_path):
    path = str(tmp_path / "krawl.db")
    dbpkg.DatabaseManager._instance = None
    db = dbpkg.DatabaseManager()
    db.initialize(database_path=path, mode="standalone")
    return db


def _attack(session, cluster_id, path, ip, ts):
    from models import AccessLog, AttackDetection

    log = AccessLog(ip=ip, path=path, method="POST", timestamp=ts, user_agent="t")
    session.add(log)
    session.flush()
    session.add(
        AttackDetection(
            access_log_id=log.id,
            attack_type="sql_injection",
            matched_pattern="x",
            cluster_id=cluster_id,
        )
    )


def test_campaigns_rank_and_total_by_hits_inside_the_window(tmp_path):
    from models import PayloadCluster
    from routes.api import build_campaign_stats

    db = _db(tmp_path)
    s = db.session
    today = datetime.combine(datetime.now().date(), datetime.min.time())
    # "old": a big lifetime count, one hit today. "new": five hits today.
    s.add_all(
        [
            PayloadCluster(
                id="old",
                representative_hash="T1OLD",
                capture_count=1000,
                first_seen=today - timedelta(days=90),
                last_seen=today + timedelta(minutes=5),
            ),
            PayloadCluster(
                id="new",
                representative_hash="T1NEW",
                capture_count=50,
                first_seen=today,
                last_seen=today + timedelta(hours=3),
            ),
        ]
    )
    s.flush()
    _attack(s, "old", "/old.php", "10.0.0.1", today + timedelta(minutes=5))
    _attack(s, "old", "/old.php", "10.0.0.1", today - timedelta(days=40))
    for i in range(5):
        _attack(
            s, "new", "/new.php", f"10.0.1.{i}", today + timedelta(hours=3, minutes=i)
        )
    s.commit()

    day = build_campaign_stats(db, 8, days=1)
    assert (len(day["slots"]), day["slot_hours"]) == (24, 1)
    assert [c["id"] for c in day["campaigns"]] == ["new", "old"]
    new, old = day["campaigns"]
    assert new["hits"] == 5 and new["activity"][3] == 5 and sum(new["activity"]) == 5
    assert new["ips"] == 5
    # Lifetime count stays available, but never sizes the row.
    assert old["hits"] == 1 and old["captures"] == 1000

    week = build_campaign_stats(db, 8, days=7)
    assert (len(week["slots"]), week["slot_hours"]) == (28, 6)
    month = build_campaign_stats(db, 8, days=30)
    assert (len(month["slots"]), month["slot_hours"]) == (30, 24)

    # A period with no member hits lists nothing, even if clusters overlap it.
    assert build_campaign_stats(db, 8, days=1, offset=5)["campaigns"] == []


def test_filename_index_keeps_names_shared_by_two_or_more_ips(tmp_path):
    from models import AccessLog, CapturedPayload

    db = _db(tmp_path)
    s = db.session
    now = datetime.now()
    for name, ips in (
        ("shared.php", ["1.1.1.1", "2.2.2.2"]),
        ("solo.php", ["3.3.3.3", "3.3.3.3"]),
    ):
        for ip in ips:
            log = AccessLog(
                ip=ip, path="/up", method="POST", timestamp=now, user_agent="t"
            )
            s.add(log)
            s.flush()
            s.add(
                CapturedPayload(
                    access_log_id=log.id, ip=ip, filename=name, size=1, timestamp=now
                )
            )
    s.commit()

    everything = db.payloads.get_global_index()
    assert {r["filename"] for r in everything["index"]} == {"shared.php", "solo.php"}
    shared = db.payloads.get_global_index(min_ips=2)
    assert [r["filename"] for r in shared["index"]] == ["shared.php"]
    assert shared["pagination"]["total"] == 1
