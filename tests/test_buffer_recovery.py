"""Transaction failures must retain forensic data and respect memory limits."""

from copy import deepcopy
from datetime import datetime

import pytest
from sqlalchemy import event

from database import core, get_database, initialize_database
from models import AccessLog, AttackDetection, CapturedPayload, RequestAsset


@pytest.fixture(autouse=True)
def empty_buffer(monkeypatch):
    from collections import deque

    monkeypatch.setattr(core, "_write_buffer", deque())
    monkeypatch.setattr(core, "_buffer_bytes", 0)
    monkeypatch.setattr(core, "_dropped_rows", 0)


def entry(**overrides):
    result = {
        "ip": "203.0.113.7",
        "path": "/upload",
        "raw_request": "POST /upload HTTP/1.1\r\n\r\npayload",
        "attack_types": ["command_injection"],
        "matched_patterns": {"command_injection": ";"},
        "file_payloads": [{"filename": "payload.php", "size": 7}],
        "target_host": "target.example",
        "request_assets": ["https://target.example/payload.php"],
    }
    result.update(overrides)
    return result


def test_retry_preserves_timestamp_detections_and_files(tmp_path):
    initialize_database(str(tmp_path / "retry.db"))
    db = get_database()
    core._buffer_access_log_entry(**entry())
    original = deepcopy(core._write_buffer[0])
    original_bytes = core.get_write_buffer_bytes()

    def fail_commit(session):
        raise RuntimeError("simulated failed commit")

    session = db.session
    event.listen(session, "before_commit", fail_commit)
    assert db.flush_access_log_buffer() == 0
    assert list(core._write_buffer) == [original]
    assert core.get_write_buffer_bytes() == original_bytes

    assert db.flush_access_log_buffer() == 1
    assert core.get_write_buffer_bytes() == 0
    session = db.session
    log = session.query(AccessLog).one()
    attack = session.query(AttackDetection).one()
    upload = session.query(CapturedPayload).one()
    asset = session.query(RequestAsset).one()
    assert log.timestamp == original["_buffered_at"]
    assert attack.access_log_id == upload.access_log_id == log.id
    assert attack.matched_pattern == ";"
    assert upload.filename == "payload.php"
    assert log.target_host == "target.example"
    assert asset.access_log_id == log.id
    assert asset.url == "https://target.example/payload.php"


@pytest.mark.parametrize("ceiling", ["rows", "bytes"])
def test_failed_batch_requeue_stays_bounded(tmp_path, monkeypatch, ceiling):
    initialize_database(str(tmp_path / "bounded.db"))
    db = get_database()
    sample_size = core._entry_bytes(entry(_buffered_at=datetime.now()))
    if ceiling == "rows":
        monkeypatch.setattr(core, "_MAX_BUFFER_ROWS", 2)
    else:
        monkeypatch.setattr(core, "_MAX_BUFFER_BYTES", sample_size * 2)
    core._buffer_access_log_entry(**entry())
    batch = db._pop_batch(1)

    def concurrent_arrivals_then_fail(session):
        core._buffer_access_log_entry(**entry())
        core._buffer_access_log_entry(**entry())
        raise RuntimeError("database unavailable")

    event.listen(db.session, "before_commit", concurrent_arrivals_then_fail)
    assert db._insert_access_log_batch(batch) == 0
    assert len(core._write_buffer) == 2
    assert core.get_dropped_rows() == 1
    assert core.get_write_buffer_bytes() == sum(
        core._entry_bytes(row) for row in core._write_buffer
    )
    assert core.get_write_buffer_bytes() <= core._MAX_BUFFER_BYTES


def test_unicode_metadata_and_single_oversized_row(monkeypatch):
    ascii_row = entry(raw_request="a" * 1000)
    unicode_row = entry(raw_request="\U0001f600" * 1000)
    assert core._entry_bytes(unicode_row) > core._entry_bytes(ascii_row) + 2900
    assert core._entry_bytes(entry(file_payloads=[{"content": b"a" * 10_000}])) > 10_000
    monkeypatch.setattr(core, "_MAX_BUFFER_BYTES", 100)
    core._buffer_access_log_entry(**unicode_row)
    assert not core._write_buffer
    assert core.get_write_buffer_bytes() == 0
    assert core.get_dropped_rows() == 1


def test_flush_respects_exact_run_limit(tmp_path):
    initialize_database(str(tmp_path / "limit.db"))
    for _ in range(5):
        core._buffer_access_log_entry(**entry())
    assert get_database().flush_access_log_buffer(max_rows=2) == 2
    assert len(core._write_buffer) == 3


def test_failed_transaction_does_not_publish_a_ban(tmp_path, monkeypatch):
    import ban_cache

    initialize_database(str(tmp_path / "ban.db"))
    db = get_database()
    monkeypatch.setattr(ban_cache, "_banned", set())
    monkeypatch.setattr(ban_cache, "_ready", True)

    def fail_commit(session):
        raise RuntimeError("failed transaction")

    event.listen(db.session, "before_commit", fail_commit)
    assert (
        db.persist_access(
            "203.0.113.7", "/probe", increment_page_visit=True, max_pages_limit=1
        )
        == 0
    )
    assert not ban_cache.is_banned("203.0.113.7")
    assert (
        db.persist_access(
            "203.0.113.7", "/probe", increment_page_visit=True, max_pages_limit=1
        )
        == 1
    )
    assert ban_cache.is_banned("203.0.113.7")
