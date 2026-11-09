#!/usr/bin/env python3

"""
Pre-retention cleanup task for Krawl honeypot.
Runs before the db-retention task to re-check old access logs that were
initially flagged as suspicious. Re-runs the same detection checks
(attack patterns, suspicious user agent, honeypot path) and only unflags
logs that no longer match any rule, so the retention job can purge them.
"""

from datetime import datetime

from database import get_database
from detection import DetectionCoordinator, get_detection
from logger import get_app_logger

# ----------------------
# TASK CONFIG
# ----------------------

TASK_CONFIG = {
    "name": "pre-retention-cleanup",
    "cron": "30 8 * * *",  # Run daily at 8:30 AM (before db-retention at 9 AM)
    "enabled": True,
    # a daily 08:30 job, same problem, and it is the heavier of the two.
    "run_when_loaded": False,
    # A shared-database sweep, and the heavier of the two.
    "single_pod": True,
}

app_logger = get_app_logger()


# ----------------------
# Same detection logic used by the tracker at request time
# ----------------------

HONEYPOT_SUBSTRINGS = [
    "/backup",
    "/admin",
    "/config",
    "/private",
    "/database",
    "phpmyadmin",
]

HONEYPOT_PATHS = {
    "/admin",
    "/admin/",
    "/backup",
    "/backup/",
    "/config",
    "/config/",
    "/private",
    "/private/",
    "/database",
    "/database/",
    "/credentials.txt",
    "/passwords.txt",
    "/admin_notes.txt",
    "/api_keys.json",
    "/.env",
    "/wp-admin",
    "/wp-admin/",
    "/phpmyadmin",
    "/phpMyAdmin/",
}


def _is_honeypot_path(path: str) -> bool:
    if path in HONEYPOT_PATHS:
        return True
    lower = path.lower()
    return any(hp in lower for hp in HONEYPOT_SUBSTRINGS)


def _is_still_suspicious(
    path: str, user_agent: str, detector: DetectionCoordinator
) -> bool:
    """Re-run the same checks the tracker uses at request time."""
    # Honeypot path check
    if _is_honeypot_path(path):
        return True

    if not user_agent:
        return True
    if detector.scan_request(path=path, user_agent=user_agent):
        return True

    return False


def main():
    """
    Re-check old suspicious access logs past the retention period.
    Unflag only those that no longer match any suspicious rule.
    """
    try:
        from config import format_duration, get_config
        from models import AccessLog, AttackDetection, CapturedPayload, RequestAsset

        config = get_config()
        retention = config.retention_recheck_suspicious
        # Rows per pass, to limit memory usage.
        batch_size = config.tasks_cleanup_batch

        db = get_database()
        session = db.session

        cutoff = datetime.now() - retention

        # Use the same detector as request-time tracking.
        detector = get_detection()

        unflagged = 0
        kept = 0
        last_id = 0

        # Process in batches to avoid loading everything into memory
        while True:
            old_logs = (
                session.query(AccessLog.id, AccessLog.path, AccessLog.user_agent)
                .filter(
                    AccessLog.id > last_id,
                    AccessLog.timestamp < cutoff,
                    AccessLog.is_suspicious,
                    # `not <column>` is Python truthiness: it collapsed to False
                    # and this query matched nothing.
                    AccessLog.is_honeypot_trigger.is_(False),
                    # URL/UA checks cannot disprove body-only detections or
                    # uploaded evidence. Never clear those logs for deletion.
                    ~session.query(AttackDetection.id)
                    .filter(AttackDetection.access_log_id == AccessLog.id)
                    .exists(),
                    ~session.query(CapturedPayload.id)
                    .filter(CapturedPayload.access_log_id == AccessLog.id)
                    .exists(),
                    ~session.query(RequestAsset.id)
                    .filter(RequestAsset.access_log_id == AccessLog.id)
                    .exists(),
                )
                .order_by(AccessLog.id)
                .limit(batch_size)
                .all()
            )

            if not old_logs:
                break
            last_id = old_logs[-1].id

            ids_to_unflag = []
            for log in old_logs:
                if _is_still_suspicious(
                    log.path,
                    log.user_agent or "",
                    detector,
                ):
                    kept += 1
                else:
                    ids_to_unflag.append(log.id)

            if ids_to_unflag:
                (
                    session.query(AccessLog)
                    .filter(AccessLog.id.in_(ids_to_unflag))
                    .update(
                        {AccessLog.is_suspicious: False},
                        synchronize_session=False,
                    )
                )
                unflagged += len(ids_to_unflag)

            session.commit()

        session.commit()

        if unflagged or kept:
            app_logger.info(
                f"[Background Task] pre-retention-cleanup: "
                f"Unflagged {unflagged}, kept {kept} suspicious logs "
                f"(older than {format_duration(retention)})"
            )
        else:
            app_logger.debug(
                "[Background Task] pre-retention-cleanup: No old suspicious logs found"
            )

    except Exception as e:
        app_logger.error(f"[Background Task] pre-retention-cleanup: Error: {e}")
    finally:
        try:
            db.close_session()
        except Exception as e:
            app_logger.error(
                f"[Background Task] pre-retention-cleanup: Error closing session: {e}"
            )
