#!/usr/bin/env python3
"""
Seed fresh "today" attack traffic so the Threats campaign chart (default
1-day view) is not empty. Inserts today-timestamped log rows whose request
bodies hash to the same families as the headline campaigns, then runs
hash-payloads so they merge in and extend those campaigns to today.

Idempotent per day: skips if it finds its own marker path (`/__seedtoday__/`).
"""

import datetime
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from seed_threat_data import _raw, _sql_inj_body, _xss_body

from database import get_database, initialize_database

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "krawl.db")

CAMPAIGNS = [
    {
        "ip": "45.155.205.201",
        "path": "/login.php",
        "n": 6,
        "body_fn": _sql_inj_body,
        "referer": "https://evil.example.com/bait-7a3f.html",
    },
    {
        "ip": "195.54.160.91",
        "path": "/feedback",
        "n": 5,
        "body_fn": _xss_body,
        "referer": "https://evil.example.com/bait-x9c2.html",
    },
    {
        "ip": "5.188.206.14",
        "path": "/admin/login",
        "n": 6,
        "body_fn": lambda v: (
            f"username=admin&password=Today{v:03d}!@#$%^&csrf=ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        ),
        "referer": "",
    },
]

_ATTACK_TYPES = {
    "/login.php": "sql_injection",
    "/feedback": "xss_attempt",
    "/admin/login": "login_attempt",
}


def main(db_path: str | None = None):
    target = os.path.abspath(db_path or DEFAULT_DB_PATH)
    if not os.path.exists(target):
        print(f"DB not found: {target}")
        return

    initialize_database(target)
    db = get_database()
    session = db.session
    try:
        from models import AccessLog, AttackDetection

        marker = session.query(AccessLog.id).filter(AccessLog.path.like("/__seedtoday__%")).first()
        if marker:
            print("Already seeded today (found /__seedtoday__*). Skipping.")
            return

        now = datetime.datetime.now()
        total_logs = 0
        for seed in CAMPAIGNS:
            ip = seed["ip"]
            path = seed["path"]
            referer = seed["referer"]
            atype = _ATTACK_TYPES[path]
            body_fn = seed["body_fn"]
            for i in range(seed["n"]):
                ts = now - datetime.timedelta(minutes=90) + datetime.timedelta(minutes=i * 6)
                body = body_fn(i)
                raw = _raw("POST", path, "application/x-www-form-urlencoded", body, referer=referer)
                al = AccessLog(
                    ip=ip,
                    path=path,
                    user_agent="Mozilla/5.0 SeedBot/1.0",
                    method="POST",
                    is_suspicious=True,
                    is_honeypot_trigger=False,
                    timestamp=ts,
                    raw_request=raw,
                    referer=referer or None,
                )
                session.add(al)
                session.flush()
                session.add(AttackDetection(access_log_id=al.id, attack_type=atype, matched_pattern=path))
                total_logs += 1

        marker_log = AccessLog(
            ip="203.0.113.250",
            path="/__seedtoday__/marker",
            user_agent="SeedMarker/1.0",
            method="GET",
            is_suspicious=False,
            is_honeypot_trigger=False,
            timestamp=now,
            raw_request=_raw("GET", "/__seedtoday__/marker", "text/plain", ""),
            referer=None,
        )
        session.add(marker_log)
        session.commit()
        print(f"Inserted {total_logs} today-dated attack logs")

        from tasks.hash_payloads import main as hash_main

        hash_main()

        clusters = db.payloads.get_campaign_clusters()
        print(f"\nCampaigns: {len(clusters)}")
        for c in clusters[:6]:
            print(
                f"  {c['rep_hash'][:8]}  ev={c['events']} ips={c['ips']} path={c['path']!r} last={c['last_seen']}"
            )

    finally:
        db.close_session()


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)