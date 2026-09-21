#!/usr/bin/env python3

"""Host targets and URL assets persist, aggregate, and backfill."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import database as dbpkg


def _raw(host: str, body: str, referer: str = "", forwarded_host: str = "") -> str:
    ref = f"Referer: {referer}\r\n" if referer else ""
    forwarded = f"X-Forwarded-Host: {forwarded_host}\r\n" if forwarded_host else ""
    return (
        "POST /xmlrpc.php HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"{ref}"
        f"{forwarded}"
        "Content-Type: text/xml\r\n\r\n"
        f"{body}"
    )


def test_request_metadata_pipeline():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "krawl.db")
        dbpkg.DatabaseManager._instance = None
        db = dbpkg.DatabaseManager()
        db.initialize(database_path=path, mode="standalone")
        dbpkg.initialize_database(path)

        from models import AccessLog, RequestAsset
        from request_metadata import extract_request_metadata
        from tracker import AccessTracker

        repeated = "https://cdn.bad.test/dropper.js"
        referer = "https://origin.example/wp-login.php"
        raw = _raw(
            "Target.Example:443",
            f"{repeated} {repeated}",
            referer,
            "backend.internal:8080",
        )
        host, assets = extract_request_metadata(raw)
        assert host == "target.example"
        assert assets == [referer, repeated, repeated]

        tracker = AccessTracker(250, 600, db_manager=db)
        tracker.record_access(
            ip="203.0.113.38",
            path="/xmlrpc.php",
            user_agent="test",
            body=f"{repeated} {repeated}",
            method="POST",
            raw_request=raw,
            referer=referer,
        )
        tracker.record_access(
            ip="198.51.100.90",
            path="/wp-login.php",
            user_agent="test",
            body=repeated,
            method="POST",
            raw_request=_raw("target.example", repeated),
        )

        domains = db.access_logs.get_targeted_domains()
        assert domains["domains"][0]["domain"] == "target.example"
        assert domains["domains"][0]["count"] == 2
        assert domains["domains"][0]["distinct_ips"] == 2

        asset_rows = {
            row["url"]: row for row in db.access_logs.get_request_assets()["assets"]
        }
        assert asset_rows[repeated]["count"] == 3
        assert asset_rows[referer]["count"] == 1

        # A retained row from before this feature is picked up by the bounded
        # scheduled task and is not duplicated on its next run.
        session = db.session
        session.add(
            AccessLog(
                ip="198.51.100.8",
                path="/legacy",
                method="GET",
                is_suspicious=True,
                is_honeypot_trigger=False,
                raw_request=_raw(
                    "legacy.example",
                    "https://legacy.example/a",
                    "https://origin.example/bait",
                ),
                request_metadata_extracted=False,
            )
        )
        multipart = (
            "--files\r\n"
            'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
            "Content-Type: application/x-php\r\n\r\n"
            "<?php echo 'generic'; ?>\r\n"
            "--files--\r\n"
        )
        session.add(
            AccessLog(
                ip="192.0.2.25",
                path="/legacy-upload",
                method="POST",
                is_suspicious=True,
                is_honeypot_trigger=False,
                raw_request=(
                    "POST /legacy-upload HTTP/1.1\r\n"
                    "Host: upload.example\r\n"
                    "Content-Type: multipart/form-data; boundary=files\r\n\r\n"
                    f"{multipart}"
                ),
                request_metadata_extracted=False,
                file_extraction_version=0,
            )
        )
        session.commit()
        db.close_session()

        from tasks.extract_request_metadata import main as backfill
        from tasks.extract_captured_files import main as file_backfill

        backfill()
        backfill()
        file_backfill()
        file_backfill()
        session = db.session
        try:
            legacy = session.query(AccessLog).filter_by(path="/legacy").one()
            assert legacy.target_host == "legacy.example"
            assert legacy.referer == "https://origin.example/bait"
            assert legacy.request_metadata_extracted is True
            assert (
                session.query(RequestAsset)
                .filter_by(access_log_id=legacy.id, url="https://legacy.example/a")
                .count()
                == 1
            )
            from models import CapturedPayload

            files = session.query(CapturedPayload).filter_by(filename="shell.php").all()
            assert len(files) == 1
            assert files[0].size == len("<?php echo 'generic'; ?>")
        finally:
            db.close_session()


if __name__ == "__main__":
    test_request_metadata_pipeline()
    print("OK: request metadata extraction, aggregation, and backfill")
