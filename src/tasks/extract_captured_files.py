"""Backfill captured-file rows from retained raw HTTP requests."""

from sqlalchemy import and_, exists, insert, or_, select, update

from config import get_config
from database import get_database
from logger import get_app_logger
from models import AccessLog, CapturedPayload
from sanitizer import sanitize_ip
from tlsh_utils import extract_file_payloads

app_logger = get_app_logger()

TASK_CONFIG = {
    "name": "extract-captured-files",
    "cron": "*/1 * * * *",
    "enabled": True,
    "run_when_loaded": False,
    "single_pod": True,
}

CURRENT_FILE_EXTRACTION_VERSION = 1
MAX_LOGS_PER_RUN = 500


def main():
    db = get_database()
    session = db.session
    try:
        rows = session.execute(
            select(AccessLog.id, AccessLog.ip, AccessLog.raw_request)
            .where(
                or_(
                    AccessLog.file_extraction_version.is_(None),
                    AccessLog.file_extraction_version < CURRENT_FILE_EXTRACTION_VERSION,
                )
            )
            .order_by(AccessLog.id.asc())
            .limit(MAX_LOGS_PER_RUN)
        ).all()

        inserted = 0
        compute_tlsh = get_config().tlsh_enabled
        for log_id, ip, raw_request in rows:
            payloads = extract_file_payloads(
                raw_request or "", compute_tlsh=compute_tlsh
            )
            for payload in payloads:
                filename = payload.get("filename") or None
                sha256 = payload.get("sha256")
                duplicate = session.scalar(
                    select(
                        exists().where(
                            and_(
                                CapturedPayload.access_log_id == log_id,
                                CapturedPayload.filename == filename,
                                CapturedPayload.sha256 == sha256,
                            )
                        )
                    )
                )
                if duplicate:
                    continue
                session.execute(
                    insert(CapturedPayload).values(
                        access_log_id=log_id,
                        ip=sanitize_ip(ip),
                        filename=filename,
                        content_type=(payload.get("content_type") or "")[:128] or None,
                        size=payload.get("size", 0),
                        tlsh_hash=payload.get("tlsh_hash"),
                        cluster_id=None,
                        sha256=sha256,
                    )
                )
                inserted += 1
            session.execute(
                update(AccessLog)
                .where(AccessLog.id == log_id)
                .values(file_extraction_version=CURRENT_FILE_EXTRACTION_VERSION)
            )
        session.commit()
        if rows:
            app_logger.info(
                f"[Background Task] extract-captured-files: processed {len(rows)} "
                f"logs, inserted {inserted} files"
                + (
                    ", batch full, more pending"
                    if len(rows) == MAX_LOGS_PER_RUN
                    else ""
                )
            )
    except Exception as exc:
        session.rollback()
        app_logger.error(f"extract-captured-files failed: {exc}")
    finally:
        db.close_session()
