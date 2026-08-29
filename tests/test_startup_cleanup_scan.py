#!/usr/bin/env python3

"""
The startup cleanup must not scan the event tables to find candidate IPs.

Background: boot hung after "Database ready" on a flooded instance. The cause
was `SELECT DISTINCT ip` over access_logs and category_history — tables that
hold one row per request, so the scan is O(traffic). An IPv6 proxy flood made
that minutes to hours of blocked startup.

Candidates only ever need to come from the tables keyed BY ip (ip_stats and
tracked_ips, both primary keys), which makes the scan an index-only walk of
the distinct set instead.

Usage: python tests/test_startup_cleanup_scan.py
"""

import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sqlalchemy import event

from database import get_database, initialize_database
from database.startup import purge_ignored_ips
from models import AccessLog, AttackDetection, CategoryHistory, IpStats

IGNORED = ["127.0.0.0/8", "10.0.0.0/8"]


def _seed(session):
    """Two ignored IPs and one public one, each with events attached."""
    for ip in ("127.0.0.1", "10.1.2.3", "203.0.113.7"):
        session.add(
            IpStats(
                ip=ip,
                total_requests=3,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
            )
        )
        for _ in range(3):
            log = AccessLog(ip=ip, path="/", method="GET", timestamp=datetime.now())
            session.add(log)
            session.flush()
            session.add(
                AttackDetection(
                    access_log_id=log.id, attack_type="scan", matched_pattern="x"
                )
            )
        session.add(
            CategoryHistory(ip=ip, new_category="attacker", timestamp=datetime.now())
        )
    session.commit()


def test_scan_avoids_event_tables():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    initialize_database(db_path)
    db = get_database()
    session = db.session
    _seed(session)

    statements = []

    def record(conn, cursor, statement, params, context, executemany):
        statements.append(" ".join(statement.split()))

    event.listen(db._engine, "before_cursor_execute", record)
    try:
        removed = purge_ignored_ips(session, IGNORED)
        session.commit()
    finally:
        event.remove(db._engine, "before_cursor_execute", record)

    # Correctness first: both ignored IPs gone from every table, public IP intact.
    assert removed == 2, f"expected 2 ignored IPs, got {removed}"
    remaining = {r.ip for r in session.query(IpStats).all()}
    assert remaining == {"203.0.113.7"}, remaining
    assert {r.ip for r in session.query(AccessLog).all()} == {"203.0.113.7"}
    assert {r.ip for r in session.query(CategoryHistory).all()} == {"203.0.113.7"}
    assert session.query(AttackDetection).count() == 3, "orphan detections left"

    # The scan itself: no SELECT may read candidate IPs out of an event table.
    # Deletes and id lookups against them are fine — those are indexed by ip.
    scans = [
        s
        for s in statements
        if s.upper().startswith("SELECT")
        and ("access_logs" in s or "category_history" in s)
        and "WHERE" not in s.upper()
    ]
    assert not scans, "startup cleanup still scans an event table:\n  " + "\n  ".join(
        scans
    )

    db.close_session()
    os.unlink(db_path)
    print("OK: candidates come from the ip-keyed tables; no event-table scan")


if __name__ == "__main__":
    test_scan_avoids_event_tables()
