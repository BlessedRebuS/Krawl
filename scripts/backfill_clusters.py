#!/usr/bin/env python3
"""
Backfill campaign clustering for historical payloads.

Rows already carrying a TLSH digest but no cluster_id (captured_payloads +
attack_detections) are run through the same incremental clustering as live
captures, in chronological order (first_seen ascending) so cluster formation
reflects real timeline order.

Historical rows that predate TLSH hashing (tlsh_hash IS NULL) stay unclustered:
raw file content / request bodies are not retained, so their hashes cannot be
recomputed. Hashing happens at ingest; only the metadata (including the digest)
is persisted.

Usage:
    .venv/bin/python scripts/backfill_clusters.py            # data/krawl.db
    KRAWL_STANDALONE_DB=/path/to.db .venv/bin/python scripts/backfill_clusters.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import database as dbpkg
from config import get_config
from models import AccessLog, AttackDetection, CapturedPayload


def main() -> None:
    cfg = get_config()
    threshold = cfg.tlsh_cluster_threshold
    db_path = os.environ.get("KRAWL_STANDALONE_DB", "data/krawl.db")
    db_path = os.path.abspath(db_path)

    dbpkg.DatabaseManager._instance = None
    db = dbpkg.DatabaseManager()
    db.initialize(database_path=db_path, mode="standalone")
    session = db.session

    # Files: hashed but unclustered, oldest first.
    files = (
        session.query(CapturedPayload)
        .filter(
            CapturedPayload.tlsh_hash.isnot(None),
            CapturedPayload.cluster_id.is_(None),
        )
        .order_by(CapturedPayload.timestamp.asc())
        .all()
    )
    # Attack bodies: hashed but unclustered, ordered by the access-log timestamp.
    attack_rows = (
        session.query(
            AttackDetection.id.label("id"),
            AttackDetection.tlsh_hash.label("tlsh_hash"),
            AccessLog.timestamp.label("stamp"),
        )
        .join(AccessLog, AttackDetection.access_log_id == AccessLog.id)
        .filter(
            AttackDetection.tlsh_hash.isnot(None),
            AttackDetection.cluster_id.is_(None),
        )
        .order_by(AccessLog.timestamp.asc())
        .all()
    )

    total = len(files) + len(attack_rows)
    assigned = 0
    session.close()

    for row in files:
        cid = db.payloads.assign_cluster(row.tlsh_hash, row.timestamp, threshold=threshold)
        if cid:
            session = db.session
            session.query(CapturedPayload).filter_by(id=row.id).update(
                {"cluster_id": cid}
            )
            session.commit()
            db.close_session()
            assigned += 1

    for row in attack_rows:
        cid = db.payloads.assign_cluster(row.tlsh_hash, row.stamp, threshold=threshold)
        if cid:
            session = db.session
            session.query(AttackDetection).filter_by(id=row.id).update(
                {"cluster_id": cid}
            )
            session.commit()
            db.close_session()
            assigned += 1

    print(f"backfill done: {assigned}/{total} rows clustered (threshold={threshold})")


if __name__ == "__main__":
    main()