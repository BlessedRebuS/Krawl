#!/usr/bin/env python3

"""
The map's paginated IP fetch must not COUNT(*) once per page.

Background: /api/all-ips?page=N&page_size=5000 hung on the demo instance. The
map walks pages sequentially until it has the requested number of IPs, and
every page recomputed `SELECT COUNT(*) FROM ip_stats` for the pagination
block. COUNT(*) has no shortcut on PostgreSQL — it walks every row — so a
flooded ip_stats made each page cost a full scan.

Usage: python tests/test_all_ips_count_cache.py
"""

import json
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sqlalchemy import event

import dashboard_cache
from database import get_database, initialize_database
from models import IpStats

N_IPS = 500
PAGE_SIZE = 50


class FakeRedis:
    """Only the two calls the table cache makes."""

    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def setex(self, key, ttl, value):
        self.store[key] = value


def test_count_is_cached_across_pages():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    initialize_database(db_path)
    db = get_database()
    session = db.session

    now = datetime.now()
    session.bulk_save_objects(
        [
            IpStats(
                ip=f"203.0.113.{i // 250}.{i % 250}",
                total_requests=i,
                first_seen=now,
                last_seen=now,
            )
            for i in range(N_IPS)
        ]
    )
    session.commit()

    # Pretend we are in scalable mode: that is where the table cache lives, and
    # where the demo instance runs.
    fake = FakeRedis()
    dashboard_cache._backend = "scalable"
    dashboard_cache._redis_client = fake

    counts = []

    def record(conn, cursor, statement, params, context, executemany):
        if "count(" in statement.lower():
            counts.append(statement)

    event.listen(db._engine, "before_cursor_execute", record)
    try:
        pages = N_IPS // PAGE_SIZE
        for page in range(1, pages + 1):
            result = db.ip_stats.get_all_ips_paginated(
                page=page, page_size=PAGE_SIZE, sort_by="last_seen", sort_order="desc"
            )
            assert result["pagination"]["total"] == N_IPS, result["pagination"]
    finally:
        event.remove(db._engine, "before_cursor_execute", record)
        dashboard_cache._backend = "standalone"
        dashboard_cache._redis_client = None

    assert len(counts) == 1, (
        f"{pages} pages issued {len(counts)} COUNT(*) queries; expected 1 "
        "(the rest must come from the cache)"
    )
    assert json.loads(fake.store["krawl:cache:table:ip_stats:count:all"]) == N_IPS

    db.close_session()
    os.unlink(db_path)
    print(f"OK: {pages} pages cost 1 COUNT(*), not {pages}")


if __name__ == "__main__":
    test_count_is_cached_across_pages()
