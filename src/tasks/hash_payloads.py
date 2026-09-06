"""Scheduled TLSH hashing + campaign clustering for attack payloads.

Runs every minute (and on load): picks up access logs that carry attack
detections but have not been hashed yet, recomputes each digest from the
persisted raw_request (or the path for bodyless hits), clusters it into a
campaign, and stamps attack_detections.tlsh_hash / cluster_id.

The watermark (payload_hash_watermark) makes each access log processed
exactly once: the first runs sweep all history (backward hashing), later
runs only touch new logs. Unhashable logs (no raw_request, short body, or
TNULL) still advance the watermark so they are never rescanned.

Captured files predating hashing are recovered in a second bounded pass,
re-extracted from their raw_request, retried until each has a digest.
"""

import urllib.parse

from config import get_config
from database import get_database
from logger import get_app_logger
from models import AccessLog, AttackDetection, CapturedPayload, PayloadHashWatermark
from tlsh_utils import tlsh_available, tlsh_hash

app_logger = get_app_logger()

# ----------------------
# TASK CONFIG
# ----------------------

TASK_CONFIG = {
    "name": "hash-payloads",
    "cron": "*/1 * * * *",
    "enabled": True,
    # Sweep history immediately at boot (and after every upgrade).
    "run_when_loaded": True,
}

# Upper bound on access logs hashed per run; the remainder is picked up
# next minute. Sized like MAX_IPS_PER_RUN in analyze_ips.
MAX_LOGS_PER_RUN = 5000


def _parse_raw_request(raw: str) -> tuple[str, str]:
    """Return (path, body) from a captured raw HTTP request string.

    Mirrors build_raw_request: METHOD /path?query HTTP/1.1\\r\\n headers\\r\\n\\r\\n body.
    """
    header = raw.partition("\r\n\r\n")[0]
    first_line = header.split("\r\n", 1)[0]
    parts = first_line.split(" ", 2)
    path = parts[1] if len(parts) > 1 else ""
    path = path.split("?", 1)[0]
    body = raw.partition("\r\n\r\n")[2]
    return path, body


def _digest_for(body: str, path: str) -> str | None:
    """Same rule as the old inline hashing: decoded body, else the path."""
    payload = urllib.parse.unquote(body) if body else path
    return tlsh_hash(payload.encode("utf-8", errors="replace"))


def _read_watermark(db) -> int:
    session = db.session
    try:
        row = session.get(PayloadHashWatermark, 1)
        return row.access_log_id if row else 0
    finally:
        db.close_session()


def _advance_watermark(db, value: int) -> None:
    session = db.session
    try:
        row = session.get(PayloadHashWatermark, 1)
        if row is None:
            session.add(PayloadHashWatermark(id=1, access_log_id=value))
        elif value > row.access_log_id:
            row.access_log_id = value
        session.commit()
    finally:
        db.close_session()


def _hash_attack_bodies(
    db, watermark: int, threshold: int
) -> tuple[int, int, int, int]:
    """Hash + cluster attack bodies for logs above the watermark.

    Returns (logs_seen, hashed, clustered, new_watermark).
    """
    session = db.session
    try:
        pending = (
            session.query(AccessLog.id, AccessLog.timestamp, AccessLog.raw_request)
            .join(AttackDetection, AttackDetection.access_log_id == AccessLog.id)
            .filter(AccessLog.id > watermark, AccessLog.raw_request.isnot(None))
            .order_by(AccessLog.id.asc())
            .limit(MAX_LOGS_PER_RUN)
            .distinct()
            .all()
        )
        if not pending:
            return 0, 0, 0, watermark

        hashed = clustered = 0
        for log_id, ts, raw in pending:
            path, body = _parse_raw_request(raw)
            digest = _digest_for(body, path)
            cid = None
            if digest:
                cid = db.payloads.assign_cluster(digest, ts, threshold=threshold)
                hashed += 1
                if cid:
                    clustered += 1
            session.query(AttackDetection).filter_by(access_log_id=log_id).update(
                {"tlsh_hash": digest, "cluster_id": cid},
                synchronize_session=False,
            )
            session.commit()
        new_watermark = pending[-1][0]
        _advance_watermark(db, new_watermark)
        return len(pending), hashed, clustered, new_watermark
    finally:
        db.close_session()


def _hash_files(db, threshold: int) -> int:
    """Backward-hash captured_payloads rows still missing a digest.

    The watermark does not gate this pass: files are only retried while they
    lack a digest, and batches are bounded per run.
    """
    from tlsh_utils import extract_file_payloads

    session = db.session
    try:
        files = (
            session.query(
                CapturedPayload.id,
                CapturedPayload.filename,
                AccessLog.timestamp,
                AccessLog.raw_request,
            )
            .join(AccessLog, AccessLog.id == CapturedPayload.access_log_id)
            .filter(
                CapturedPayload.tlsh_hash.is_(None), AccessLog.raw_request.isnot(None)
            )
            .limit(MAX_LOGS_PER_RUN)
            .all()
        )
        stamped = 0
        for fid, fname, ts, raw in files:
            for ext in extract_file_payloads(raw):
                if not ext.get("filename") == fname or not ext.get("tlsh_hash"):
                    continue
                cid = db.payloads.assign_cluster(
                    ext["tlsh_hash"], ts, threshold=threshold
                )
                session.query(CapturedPayload).filter_by(id=fid).update(
                    {"tlsh_hash": ext["tlsh_hash"], "cluster_id": cid},
                    synchronize_session=False,
                )
                session.commit()
                stamped += 1
                break
        return stamped
    finally:
        db.close_session()


def main():
    config = get_config()
    if not (config.tlsh_enabled and tlsh_available()):
        app_logger.debug(
            "[Background Task] hash-payloads: TLSH disabled or unavailable, skipping"
        )
        return
    db = get_database()
    threshold = config.tlsh_cluster_threshold

    watermark = _read_watermark(db)
    processed, hashed, clustered, _ = _hash_attack_bodies(db, watermark, threshold)
    _hash_files(db, threshold)
    if processed:
        app_logger.info(
            f"[Background Task] hash-payloads: {processed} logs, "
            f"{hashed} hashed, {clustered} clustered"
        )
