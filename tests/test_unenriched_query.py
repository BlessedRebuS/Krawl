#!/usr/bin/env python3

"""
Regression check for IpStatsRepo.get_unenriched_ips().

The enrichment task takes a capped batch each run. Two properties keep that batch
useful, and both were broken before:

1. Rows that are already enriched must not come back. "City is empty" is not the
   same as "not enriched" — many datacenter ranges have no city — so including
   city in the filter left enriched rows matching forever.
2. The batch must be ordered newest-activity-first. Without it the batch was
   filled in physical row order, so with a 611k backlog the newly seen IPs shown
   in every "recent" dashboard view were never reached.

Usage: python tests/test_unenriched_query.py
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.ip_stats import IpStatsRepo
from models import Base, IpStats


class _FakeDb:
    """Minimal stand-in for DatabaseManager: a session and a no-op close."""

    def __init__(self, session):
        self._session = session

    @property
    def session(self):
        return self._session

    def close_session(self):
        pass


def _run():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    now = datetime.now()

    session.add_all(
        [
            # Enriched, but the provider returned no city. Used to match the
            # "unenriched" filter forever and monopolise every batch.
            IpStats(
                ip="203.0.113.1",
                last_seen=now - timedelta(days=30),
                country_code="US",
                city=None,
                latitude=37.7,
                longitude=-122.4,
            ),
            # Fully enriched.
            IpStats(
                ip="203.0.113.2",
                last_seen=now - timedelta(days=20),
                country_code="DE",
                city="Berlin",
                latitude=52.5,
                longitude=13.4,
            ),
            # Never enriched, seen a while ago.
            IpStats(ip="203.0.113.3", last_seen=now - timedelta(days=10)),
            # Never enriched, seen just now — an active attacker.
            IpStats(ip="203.0.113.4", last_seen=now),
        ]
    )
    session.commit()

    repo = IpStatsRepo(_FakeDb(session))
    got = repo.get_unenriched_ips(limit=50)

    assert (
        "203.0.113.1" not in got
    ), f"enriched row with no city must not be re-queued, got {got}"
    assert "203.0.113.2" not in got, f"fully enriched row must not be queued, got {got}"
    assert got == [
        "203.0.113.4",
        "203.0.113.3",
    ], f"expected only un-geolocated IPs, newest first, got {got}"

    # The cap must not be spent on the oldest rows.
    assert repo.get_unenriched_ips(limit=1) == [
        "203.0.113.4"
    ], "a capped batch must start with the most recently seen IP"

    print("OK: get_unenriched_ips returns only un-geolocated IPs, newest first")


if __name__ == "__main__":
    _run()
