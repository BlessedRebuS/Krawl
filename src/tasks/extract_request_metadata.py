"""Backfill Host targets and URL assets from retained raw HTTP requests."""

from sqlalchemy import insert, select, update

from database import get_database
from logger import get_app_logger
from models import AccessLog, RequestAsset
from request_metadata import extract_request_metadata, extract_request_referer
from sanitizer import sanitize_path

app_logger = get_app_logger()

TASK_CONFIG = {
    "name": "extract-request-metadata",
    "cron": "*/1 * * * *",
    "enabled": True,
    "run_when_loaded": False,
    "single_pod": True,
}

MAX_LOGS_PER_RUN = 500


def main():
    db = get_database()
    session = db.session
    try:
        rows = session.execute(
            select(AccessLog.id, AccessLog.raw_request, AccessLog.referer)
            .where(AccessLog.request_metadata_extracted.is_(False))
            .order_by(AccessLog.id.asc())
            .limit(MAX_LOGS_PER_RUN)
        ).all()

        for log_id, raw_request, existing_referer in rows:
            target_host, assets = extract_request_metadata(raw_request or "")
            referer = existing_referer or extract_request_referer(raw_request or "")
            session.execute(
                update(AccessLog)
                .where(AccessLog.id == log_id)
                .values(
                    target_host=target_host,
                    referer=sanitize_path(referer) if referer else None,
                    request_metadata_extracted=True,
                )
            )
            if assets:
                session.execute(
                    insert(RequestAsset),
                    [
                        {"access_log_id": log_id, "url": sanitize_path(url)}
                        for url in assets
                    ],
                )
        session.commit()
        if rows:
            app_logger.info(
                f"[Background Task] extract-request-metadata: processed {len(rows)} logs"
                + (
                    ", batch full, more pending"
                    if len(rows) == MAX_LOGS_PER_RUN
                    else ""
                )
            )
    except Exception as exc:
        session.rollback()
        app_logger.error(f"extract-request-metadata failed: {exc}")
    finally:
        db.close_session()
