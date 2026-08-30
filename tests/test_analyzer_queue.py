#!/usr/bin/env python3

"""
The analyzer queue must drain every IP, not the same alphabetical head.

Background: IPs were staying uncategorised. get_ips_needing_reevaluation()
returned every matching row with no LIMIT, and analyze-ips then took
`sorted(ips)[:2000]` — lexicographically. With a backlog larger than one batch
the same low addresses were re-picked every minute and the tail of the address
space was never analysed at all.

Ordering by last_analysis (nulls first) is self-rotating: analysing an IP
stamps it, which sends it to the back of the queue.

Usage: python tests/test_analyzer_queue.py
"""

import os
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from database import get_database, initialize_database
from models import IpStats

N_IPS = 500
BATCH = 100


def test_queue_rotates_and_drains():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    initialize_database(db_path)
    db = get_database()
    session = db.session

    now = datetime.now()
    # Never-analysed IPs spread across the address space, so a lexicographic
    # cut would always favour the same end.
    session.bulk_save_objects(
        [
            IpStats(
                ip=f"{10 + i % 200}.0.113.{i}",
                total_requests=1,
                first_seen=now,
                last_seen=now - timedelta(seconds=i),
                last_analysis=None,
                need_reevaluation=False,
            )
            for i in range(N_IPS)
        ]
    )
    session.commit()

    # The limit must be applied in SQL, not by the caller.
    batch = db.ip_stats.get_ips_needing_reevaluation(limit=BATCH)
    assert len(batch) == BATCH, len(batch)

    # Drain the whole backlog in batches, marking each as analysed, exactly as
    # analyze-ips does. Every IP must be reached.
    seen: set[str] = set()
    for _ in range(N_IPS // BATCH):
        batch = db.ip_stats.get_ips_needing_reevaluation(limit=BATCH)
        assert batch, "queue emptied early"
        overlap = seen & set(batch)
        assert not overlap, f"{len(overlap)} IPs re-picked before the rest were seen"
        seen.update(batch)
        for ip in batch:
            db.ip_stats.mark_analysed(ip, datetime.now())

    assert len(seen) == N_IPS, f"only {len(seen)} of {N_IPS} IPs were ever queued"
    assert db.ip_stats.get_ips_needing_reevaluation(limit=BATCH) == [], (
        "queue not drained"
    )

    # A newly flagged IP jumps ahead of the analysed ones.
    session.query(IpStats).filter(IpStats.ip == "10.0.113.0").update(
        {"need_reevaluation": True}
    )
    session.commit()
    assert db.ip_stats.get_ips_needing_reevaluation(limit=BATCH) == ["10.0.113.0"]

    db.close_session()
    os.unlink(db_path)
    print(f"OK: all {N_IPS} IPs queued in {N_IPS // BATCH} batches, none starved")


if __name__ == "__main__":
    test_queue_rotates_and_drains()
