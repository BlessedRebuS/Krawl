#!/usr/bin/env python3

"""End-to-end check: referer + TLSH + captured file payloads persist through
tracker.record_access -> database.persist_access (standalone path)."""

import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import database as dbpkg  # noqa: E402


def build_raw_request(method, path, content_type, body=""):
    return (
        f"{method} {path} HTTP/1.1\r\n"
        "Host: krawl.test\r\n"
        f"Content-Type: {content_type}\r\n"
        "User-Agent: test-agent\r\n"
        f"\r\n{body}"
    )


def main():
    with tempfile.TemporaryDirectory() as tmp:
        dbpkg.DatabaseManager._instance = None
        db = dbpkg.DatabaseManager()
        db.initialize(database_path=os.path.join(tmp, "krawl.db"), mode="standalone")
        # The scheduled tasks resolve get_database() (a module-level manager),
        # not the _instance singleton; init it against the same file so the
        # task runs in the test write to the DB the assertions read.
        dbpkg.initialize_database(os.path.join(tmp, "krawl.db"))

        from config import get_config
        from models import CapturedPayload
        from tlsh_utils import (
            SIMILARITY_THRESHOLD,
            tlsh_available,
            tlsh_diff,
            tlsh_hash,
        )
        from tracker import AccessTracker

        cfg = get_config()
        tracker = AccessTracker(
            cfg.max_pages_limit, cfg.ban_duration_seconds, db_manager=db
        )

        big = "<?php system(\\'x\\'); ?>" + "A9bC7dX2eF" * 60
        multipart_body = (
            f'--xxx\r\nContent-Disposition: form-data; name="file"; filename="c99shell.php"\r\n'
            f"Content-Type: application/x-php\r\n\r\n{big}\r\n--xxx--\r\n"
        )
        code = tracker.record_access(
            ip="203.0.113.9",
            path="/upload.php",
            user_agent="UA",
            body="a=b",
            method="POST",
            raw_request=build_raw_request(
                "POST",
                "/upload.php",
                "multipart/form-data; boundary=xxx",
                multipart_body,
            ),
            referer="http://evil.example.com/bait.php",
            file_payloads=[
                {
                    "filename": "c99shell.php",
                    "content_type": "application/x-php",
                    "size": len(big),
                    "tlsh_hash": "T179E0F1CABEAA03FD5ABA1741C04CF490938454BA3419C09FA018516619CD0ABE420409",
                    "sha256": "b" * 64,
                }
            ],
        )
        assert code is not None, "record_access returned no code"

        con = sqlite3.connect(os.path.join(tmp, "krawl.db"))
        try:
            assert con.execute("SELECT COUNT(*) FROM access_logs").fetchone()[0] == 1
            ref = con.execute("SELECT referer FROM access_logs").fetchone()[0]
            assert ref == "http://evil.example.com/bait.php", ref
            payloads = con.execute(
                "SELECT filename, tlsh_hash, sha256, access_log_id FROM captured_payloads"
            ).fetchall()
            assert len(payloads) == 1, payloads
            fname, tl, sha, log_id = payloads[0]
            assert fname == "c99shell.php", fname
            assert tl.startswith("T"), tl
            assert len(sha) == 64, sha
            assert log_id == 1, log_id
        finally:
            con.close()

        if tlsh_available():
            base = "<?php system('x'); ?>" + "".join(
                f"{c}{i}{c}{i * 2}" for c in "abcXYZ0129" for i in range(6)
            )
            variant = base.replace("system('", "shell_ex('")
            unrelated = "SELECT pg_sleep FROM information_schema.tables WHERE 1=1 -- " * 4
            h_base = tlsh_hash(base.encode())
            h_var = tlsh_hash(variant.encode())
            h_un = tlsh_hash(unrelated.encode())
            assert h_base and h_var and h_un, "TLSH returned None for test payloads"
            assert h_var != h_base, "mutated payload must not hash identically"
            assert tlsh_diff(h_base, h_var) <= SIMILARITY_THRESHOLD, tlsh_diff(h_base, h_var)
            assert tlsh_diff(h_base, h_un) > SIMILARITY_THRESHOLD, tlsh_diff(h_base, h_un)

            # Integration: a body-flagged attack must land with a TLSH hash
            # and campaign cluster_id via the scheduled hash-payloads task
            # (hashing moved off the ingest path).
            attack_body = (
                "username=admin&password=x' OR '1'='1'--"
                "&csrf="
                + "R4nd0m" * 8
                + "A9bC7dX2eF" * 4
            )
            tracker.record_access(
                ip="198.51.100.9",
                path="/login.php",
                user_agent="UA",
                body=attack_body,
                method="POST",
                raw_request=build_raw_request(
                    "POST",
                    "/login.php",
                    "application/x-www-form-urlencoded",
                    attack_body,
                ),
            )
            from models import AttackDetection as AD

            live_dets = db.session.query(AD).all()
            assert live_dets, "no attack detections recorded"
            for d in live_dets:
                assert d.tlsh_hash is None, (
                    "ingest must not hash inline; hashing is task-deferred"
                )
            db.close_session()  # release the read transaction before the task sweeps

            from tasks.hash_payloads import main as hash_payloads_main

            hash_payloads_main()
            post = db.session.query(AD).all()
            for d in post:
                assert d.tlsh_hash, f"{d.attack_type} row missing TLSH hash"
                assert d.cluster_id, f"{d.attack_type} row missing cluster_id"
            from models import PayloadHashWatermark as WM

            wm = db.session.get(WM, 1)
            assert wm and wm.access_log_id >= max(d.access_log_id for d in post), (
                f"watermark at {wm.access_log_id if wm else None}, expected >= "
                f"{max(d.access_log_id for d in post)}"
            )
            db.close_session()

            db.payloads.add_payload(
                access_log_id=1,
                ip="198.51.100.4",
                filename="c99shell-v2.php",
                content_type="application/x-php",
                size=len(variant),
                tlsh_hash=h_var,
                sha256="c" * 64,
            )
            db.payloads.add_payload(
                access_log_id=1,
                ip="198.51.100.5",
                filename="unrelated.txt",
                content_type="text/plain",
                size=len(unrelated),
                tlsh_hash=h_un,
                sha256="d" * 64,
            )
            similar = db.payloads.get_similar_events(base_hash=h_base)
            names = {r["filename"] for r in similar if r["kind"] == "file"}
            assert "c99shell-v2.php" in names, names
            assert "unrelated.txt" not in names, names
            print("fuzzy similar events clustering: OK")

            # Incremental campaign clustering (instruction 5/8).
            from datetime import datetime, timedelta

            t0 = datetime(2026, 1, 1, 12, 0, 0)
            c1 = db.payloads.assign_cluster(h_base, t0)
            assert c1, "identical digest must seed a cluster"
            c1_again = db.payloads.assign_cluster(h_base, t0 + timedelta(hours=1))
            assert c1_again == c1, "identical digest must join the same cluster"
            c2 = db.payloads.assign_cluster(h_var, t0 + timedelta(hours=2))
            assert c2 == c1, "near-variant (diff<=threshold) must join the same cluster"
            c3 = db.payloads.assign_cluster(h_un, t0 + timedelta(hours=3))
            assert c3 != c1, "unrelated digest must seed a separate cluster"
            assert db.payloads.assign_cluster(None, t0) is None
            s = db.session
            s.query(CapturedPayload).filter(
                CapturedPayload.filename == "c99shell-v2.php"
            ).update({"cluster_id": c1})
            s.query(CapturedPayload).filter(
                CapturedPayload.filename == "unrelated.txt"
            ).update({"cluster_id": c3})
            s.commit()
            db.close_session()
            campaigns = db.payloads.get_campaign_clusters()
            c_row = next(c for c in campaigns if c["id"] == c1)
            assert c_row["events"] >= 3, c_row  # capture_count from incremental assigns
            assert c_row["ips"] >= 1, c_row
            assert any(c["id"] == c3 and c["events"] == 1 for c in campaigns), campaigns
            members = db.payloads.get_cluster_events(c1)
            assert any(m["filename"] == "c99shell-v2.php" for m in members), members

            # One request flagged by several detectors must render as a single
            # grouped row (common_probes + sql_injection + ... on one upload).
            from models import AccessLog

            login_log_ids = [
                r[0]
                for r in db.session.query(AccessLog.id)
                .filter(AccessLog.path == "/login.php")
                .all()
            ]
            assert login_log_ids, "no access log for the login.php attack"
            det_rows = (
                db.session.query(AD.tlsh_hash, AD.attack_type)
                .filter(AD.access_log_id.in_(login_log_ids))
                .all()
            )
            assert det_rows, "no detections for the login.php attack"
            hash0 = det_rows[0][0]
            assert hash0, "login attack has no TLSH hash"
            expected = sorted({t for _, t in det_rows})
            # A second sweep finds nothing new (watermark advanced past these).
            hash_payloads_main()
            c_attack = (
                db.session.query(AD.cluster_id)
                .filter(AD.access_log_id.in_(login_log_ids))
                .first()
            )
            assert c_attack and c_attack[0], "job did not stamp a cluster on the attack"
            c_attack = c_attack[0]
            db.close_session()
            attack_rows = [
                m for m in db.payloads.get_cluster_events(c_attack)
                if m["kind"] == "attack"
            ]
            assert len(attack_rows) == 1, attack_rows
            assert sorted(attack_rows[0]["attack_types"]) == expected, attack_rows
            print("grouped multi-detection campaign rows: OK")
            print("incremental campaign clustering: OK")
        else:  # pragma: no cover
            print("fuzzy similar events: SKIPPED (py-tlsh not installed)")
        print("threat capture standalone persistence: OK")


if __name__ == "__main__":
    main()