"""Summary tiles: recent attackers and active time-bans."""

import os
import tempfile
from datetime import datetime, timedelta

import database as dbpkg
import metrics_counters as mc
from models import IpStats


def test_dashboard_counts_recent_attackers(monkeypatch):
    monkeypatch.setattr(mc, "_counters", {})
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "krawl.db")
        dbpkg.DatabaseManager._instance = None
        db = dbpkg.DatabaseManager()
        db.initialize(database_path=path, mode="standalone")
        dbpkg.initialize_database(path)
        now = datetime.now()
        session = db.session
        for ip, category, seen in (
            ("93.69.70.1", "attacker", now - timedelta(hours=1)),
            ("93.69.70.2", "attacker", now - timedelta(days=3)),
            ("93.69.70.3", "regular_user", now),
        ):
            session.add(
                IpStats(ip=ip, category=category, first_seen=seen, last_seen=seen)
            )
        session.commit()
        db.close_session()

        counts = db.access_logs.get_dashboard_counts()
        assert counts["unique_attackers"] == 2
        assert counts["active_attackers_24h"] == 1
        assert counts["timed_out_ips"] == 0
