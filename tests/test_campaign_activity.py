"""Threats tab: artifact tables filter by how many IPs share a value."""

import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import database as dbpkg  # noqa: E402


def _db(tmp_path):
    path = str(tmp_path / "krawl.db")
    dbpkg.DatabaseManager._instance = None
    db = dbpkg.DatabaseManager()
    db.initialize(database_path=path, mode="standalone")
    return db


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
