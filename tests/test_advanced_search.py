"""Advanced request search keeps header names and values on the same line."""

import os
import tempfile

import database as dbpkg
from database.access_logs import _matches_headers
from models import AccessLog


def test_header_matching_ignores_body_and_other_headers():
    raw = (
        "GET /.git/objects/f1/test HTTP/1.1\r\n"
        "Host: demo.krawlme.com\r\n"
        "Priority: u=0, i\r\n"
        "Referer: https://demo.krawlme.com/das_dashboard\r\n\r\n"
        "priority: secret-in-body"
    )
    assert _matches_headers(raw, [("priority", "")])
    assert _matches_headers(raw, [("PRIORITY", "u=0")])
    assert _matches_headers(raw, [("priority", "u=0"), ("referer", "das_dashboard")])
    assert not _matches_headers(raw, [("priority", "das_dashboard")])
    assert not _matches_headers(raw, [("priority", "secret-in-body")])
    assert not _matches_headers(raw, [("x-priority", "")])


def test_advanced_search_combines_fields_headers_and_pagination():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "krawl.db")
        dbpkg.DatabaseManager._instance = None
        db = dbpkg.DatabaseManager()
        db.initialize(database_path=path, mode="standalone")
        dbpkg.initialize_database(path)
        session = db.session
        for ip, host, header, body in (
            ("93.69.70.20", "demo.krawlme.com", "Priority: u=0, i", "<?php //Pass: xleet token_100% ?>"),
            ("93.69.70.21", "demo.krawlme.com", "Priority: u=1", "ordinary body"),
            ("93.69.70.22", "other.example", "X-Test: u=0, i", "xleet in another upload"),
        ):
            session.add(AccessLog(
                ip=ip, path="/.git/objects/f1/test", method="GET",
                target_host=host, referer="https://demo.krawlme.com/das_dashboard",
                user_agent="Firefox/156.0",
                raw_request=f"GET /.git/objects/f1/test HTTP/1.1\r\nHost: {host}\r\n{header}\r\n\r\n{body}",
            ))
        session.commit()
        db.close_session()
        result = db.access_logs.search_requests(
            path="/.git/objects/", host="demo.krawlme.com", method="GET",
            referer="das_dashboard", headers=[("priority", "u=0")],
        )
        assert result["pagination"]["total"] == 1
        assert result["requests"][0]["ip"] == "93.69.70.20"
        all_priority = db.access_logs.search_requests(headers=[("priority", "")], page_size=1)
        assert all_priority["pagination"]["total"] == 2
        assert len(all_priority["requests"]) == 1
        raw_matches = db.access_logs.search_requests(raw_text="XLEET", page_size=1)
        assert raw_matches["pagination"]["total"] == 2
        assert len(raw_matches["requests"]) == 1
        combined = db.access_logs.search_requests(
            host="demo.krawlme.com", raw_text="xleet",
            headers=[("priority", "u=0")],
        )
        assert [row["ip"] for row in combined["requests"]] == ["93.69.70.20"]
        assert db.access_logs.search_requests(raw_text="Priority: u=1")["pagination"]["total"] == 1
        assert db.access_logs.search_requests(raw_text="token_100%")["pagination"]["total"] == 1
