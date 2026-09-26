#!/usr/bin/env python3
"""Seed local captured HTTP requests across a branched set of DNS hosts.

This writes synthetic requests to a Krawl SQLite database; it makes no network
connections. Re-running against the same database is safe: the marker path
prevents duplicate traffic. Use --db to seed a disposable test database.
"""

import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

from sqlalchemy import insert, select

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from database import get_database, initialize_database
from models import AccessLog, IpStats
from request_metadata import CURRENT_METADATA_VERSION

MARKER_PREFIX = "/__seed_domain_map__/"
HOSTS = (
    "example.com",
    "api.example.com",
    "www.example.com",
    "login.example.com",
    "v2.api.example.com",
    "admin.v2.api.example.com",
    "edge.eu.example.com",
    "node.edge.eu.example.com",
    "krawlme.com",
    "auth.krawlme.com",
    "cdn.krawlme.com",
    "telemetry.krawlme.com",
    "v1.auth.krawlme.com",
    "static.cdn.krawlme.com",
    "collector.eu.telemetry.krawlme.com",
    "node.collector.eu.telemetry.krawlme.com",
    "sensor.co.uk",
    "api.sensor.co.uk",
    "portal.sensor.co.uk",
    "metrics.sensor.co.uk",
    "v3.api.sensor.co.uk",
    "admin.v3.api.sensor.co.uk",
    "ingest.metrics.sensor.co.uk",
    "edge.ingest.metrics.sensor.co.uk",
)
IPS = tuple(f"203.0.113.{octet}" for octet in range(101, 125))


def seed(db_path: Path, per_host: int) -> tuple[int, Counter]:
    if per_host < 1:
        raise ValueError("--per-host must be positive")
    if not db_path.is_file():
        raise FileNotFoundError(f"Database does not exist: {db_path}")

    initialize_database(str(db_path))
    db = get_database()
    session = db.session
    try:
        existing = session.execute(
            select(AccessLog.id).where(AccessLog.path.like(f"{MARKER_PREFIX}%")).limit(1)
        ).first()
        if existing:
            print("Domain map seed already present; skipped duplicate requests.")
            return 0, Counter()

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        ip_counts: Counter = Counter()
        batch = []
        for host_number, host in enumerate(HOSTS):
            for request_number in range(per_host):
                sequence = host_number * per_host + request_number
                ip = IPS[(request_number + host_number * 7) % len(IPS)]
                path = f"{MARKER_PREFIX}{host_number:02d}/{request_number:05d}"
                timestamp = now - timedelta(minutes=59) + timedelta(
                    seconds=sequence % 3500
                )
                raw = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    "User-Agent: KrawlMapSeed/1.0\r\n"
                    "Accept: */*\r\n\r\n"
                )
                batch.append({
                    "ip": ip,
                    "path": path,
                    "user_agent": "KrawlMapSeed/1.0",
                    "method": "GET",
                    "is_suspicious": False,
                    "is_honeypot_trigger": False,
                    "timestamp": timestamp,
                    "raw_request": raw,
                    "target_host": host,
                    "request_metadata_extracted": True,
                    "request_metadata_version": CURRENT_METADATA_VERSION,
                    "file_extraction_version": 1,
                })
                ip_counts[ip] += 1
                if len(batch) == 1000:
                    session.execute(insert(AccessLog), batch)
                    batch.clear()
        if batch:
            session.execute(insert(AccessLog), batch)

        for ip, count in ip_counts.items():
            stats = session.get(IpStats, ip)
            if stats is None:
                session.add(IpStats(
                    ip=ip, total_requests=count,
                    first_seen=now - timedelta(minutes=59), last_seen=now,
                ))
            else:
                stats.total_requests += count
                stats.first_seen = min(stats.first_seen, now - timedelta(minutes=59))
                stats.last_seen = max(stats.last_seen, now)
        session.commit()
        return len(HOSTS) * per_host, ip_counts
    except Exception:
        session.rollback()
        raise
    finally:
        db.close_session()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db", type=Path, default=PROJECT_ROOT / "data" / "krawl.db",
        help="Existing local SQLite database (default: data/krawl.db)",
    )
    parser.add_argument(
        "--per-host", type=int, default=1000,
        help="Requests per host (default: 1000)",
    )
    args = parser.parse_args()
    inserted, ip_counts = seed(args.db.resolve(), args.per_host)
    if inserted:
        print(
            f"Inserted {inserted:,} synthetic requests across {len(HOSTS)} hosts "
            f"and {len(ip_counts)} IPs into {args.db.resolve()}"
        )
        print("Roots: example.com, krawlme.com, sensor.co.uk")


if __name__ == "__main__":
    main()
