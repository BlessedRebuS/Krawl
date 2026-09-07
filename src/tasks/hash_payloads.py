"""Scheduled TLSH hashing + campaign clustering for attack payloads.

Runs every minute: picks up access logs that carry attack detections but have
not been hashed yet, recomputes each digest from the persisted raw_request (or
the path for bodyless hits), clusters it into a campaign, and stamps
attack_detections.tlsh_hash / cluster_id. Each run takes a bounded slice
(MAX_LOGS_PER_RUN) in CHUNK_SIZE pieces, so history is swept over many runs
rather than in one memory-hungry pass at boot.

The watermark (payload_hash_watermark) makes each access log processed
exactly once: the first runs sweep all history (backward hashing), later
runs only touch new logs. Unhashable logs (no raw_request, short body, or
TNULL) still advance the watermark so they are never rescanned.

Captured files predating hashing are recovered in a second bounded pass,
re-extracted from their raw_request, retried until each has a digest.
"""

import urllib.parse

from sqlalchemy import select, update

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
    # runs every minute anyway; a boot run only piles the history sweep on top
    # of startup, which is how this OOM-killed the pod into a crash loop.
    "run_when_loaded": False,
}

# Upper bound on access logs hashed per run; the remainder is picked up next
# minute. Deliberately modest: raw_request bodies are multi-KB and the pod
# runs with a 256Mi limit, so history is swept a slice at a time.
MAX_LOGS_PER_RUN = 500
# Raw requests held in memory at once. The watermark advances per chunk, so a
# restart mid-run resumes instead of replaying the whole batch.
CHUNK_SIZE = 50
# Captured files back-filled per run (each also loads a raw_request).
MAX_FILES_PER_RUN = 50


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


def _pending_log_ids(db, watermark: int) -> list[int]:
    """Access log ids above the watermark that carry attack detections.

    Read straight off the indexed attack_detections.access_log_id: the join to
    access_logs with DISTINCT made the DB de-duplicate multi-KB raw_request
    values for every candidate row, which is what blew up on large histories.
    """
    session = db.session
    try:
        return list(
            session.execute(
                select(AttackDetection.access_log_id)
                .where(AttackDetection.access_log_id > watermark)
                .distinct()
                .order_by(AttackDetection.access_log_id.asc())
                .limit(MAX_LOGS_PER_RUN)
            ).scalars()
        )
    finally:
        db.close_session()


def _hash_attack_bodies(
    db, watermark: int, threshold: int
) -> tuple[int, int, int, int]:
    """Hash + cluster attack bodies for logs above the watermark, CHUNK_SIZE
    raw requests in memory at a time.

    Returns (logs_seen, hashed, clustered, new_watermark).
    """
    log_ids = _pending_log_ids(db, watermark)
    if not log_ids:
        return 0, 0, 0, watermark

    reps = db.payloads.cluster_reps()
    hashed = clustered = 0
    for start in range(0, len(log_ids), CHUNK_SIZE):
        chunk = log_ids[start : start + CHUNK_SIZE]
        session = db.session
        try:
            rows = session.execute(
                select(AccessLog.id, AccessLog.timestamp, AccessLog.raw_request).where(
                    AccessLog.id.in_(chunk)
                )
            ).all()
        finally:
            db.close_session()

        # Cluster first (assign_cluster runs its own session), then stamp the
        # whole chunk in one transaction.
        stamps = []
        for log_id, ts, raw in rows:
            digest = None
            if raw:
                path, body = _parse_raw_request(raw)
                digest = _digest_for(body, path)
            cid = None
            if digest:
                cid = db.payloads.assign_cluster(
                    digest, ts, threshold=threshold, reps=reps
                )
                hashed += 1
                if cid:
                    clustered += 1
            stamps.append((log_id, digest, cid))

        session = db.session
        try:
            for log_id, digest, cid in stamps:
                session.execute(
                    update(AttackDetection)
                    .where(AttackDetection.access_log_id == log_id)
                    .values(tlsh_hash=digest, cluster_id=cid)
                )
            session.commit()
        finally:
            db.close_session()
        # Per-chunk, so an interrupted run still makes progress. Logs without a
        # raw_request are stamped NULL and pass the watermark for good.
        _advance_watermark(db, chunk[-1])
    return len(log_ids), hashed, clustered, log_ids[-1]


def _hash_files(db, threshold: int, reps) -> int:
    """Backward-hash captured_payloads rows still missing a digest.

    The watermark does not gate this pass: files are only retried while they
    lack a digest, and each run takes at most MAX_FILES_PER_RUN of them (oldest
    first) so the raw_request bodies stay a bounded slice.
    """
    from tlsh_utils import extract_file_payloads

    session = db.session
    try:
        files = session.execute(
            select(
                CapturedPayload.id,
                CapturedPayload.filename,
                AccessLog.timestamp,
                AccessLog.raw_request,
            )
            .join(AccessLog, AccessLog.id == CapturedPayload.access_log_id)
            .where(
                CapturedPayload.tlsh_hash.is_(None), AccessLog.raw_request.isnot(None)
            )
            .order_by(CapturedPayload.id.asc())
            .limit(MAX_FILES_PER_RUN)
        ).all()
    finally:
        db.close_session()

    stamped = 0
    for fid, fname, ts, raw in files:
        for ext in extract_file_payloads(raw):
            if not ext.get("filename") == fname or not ext.get("tlsh_hash"):
                continue
            cid = db.payloads.assign_cluster(
                ext["tlsh_hash"], ts, threshold=threshold, reps=reps
            )
            session = db.session
            try:
                session.execute(
                    update(CapturedPayload)
                    .where(CapturedPayload.id == fid)
                    .values(tlsh_hash=ext["tlsh_hash"], cluster_id=cid)
                )
                session.commit()
            finally:
                db.close_session()
            stamped += 1
            break
    return stamped


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
    _hash_files(db, threshold, db.payloads.cluster_reps())
    if processed:
        app_logger.info(
            f"[Background Task] hash-payloads: {processed} logs, "
            f"{hashed} hashed, {clustered} clustered"
            + (", batch full, more pending" if processed == MAX_LOGS_PER_RUN else "")
        )
