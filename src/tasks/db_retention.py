#!/usr/bin/env python3

"""
Database retention task for Krawl honeypot.
Periodically deletes old records based on configured retention_days.
"""

from datetime import datetime, timedelta

from database import get_database
from logger import get_app_logger

# ----------------------
# TASK CONFIG
# ----------------------

TASK_CONFIG = {
    "name": "db-retention",
    "cron": "0 3 * * *",  # Run daily at 3 AM
    "enabled": True,
    "run_when_loaded": False,
}

app_logger = get_app_logger()


def main():
    """
    Delete access logs, credential attempts, and attack detections
    older than the configured retention period.
    """
    try:
        from config import get_config
        from models import AccessLog, CredentialAttempt, AttackDetection

        config = get_config()
        retention_days = config.database_retention_days

        db = get_database()
        session = db.session

        cutoff = datetime.now() - timedelta(days=retention_days)

        # Delete attack detections linked to old access logs first (FK constraint)
        old_log_ids = session.query(AccessLog.id).filter(AccessLog.timestamp < cutoff)
        detections_deleted = (
            session.query(AttackDetection)
            .filter(AttackDetection.access_log_id.in_(old_log_ids))
            .delete(synchronize_session=False)
        )

        # Delete old access logs
        logs_deleted = (
            session.query(AccessLog)
            .filter(AccessLog.timestamp < cutoff)
            .delete(synchronize_session=False)
        )

        # Delete old credential attempts
        creds_deleted = (
            session.query(CredentialAttempt)
            .filter(CredentialAttempt.timestamp < cutoff)
            .delete(synchronize_session=False)
        )

        session.commit()

        if logs_deleted or creds_deleted or detections_deleted:
            app_logger.info(
                f"DB retention: Deleted {logs_deleted} access logs, "
                f"{detections_deleted} attack detections, "
                f"{creds_deleted} credential attempts older than {retention_days} days"
            )

    except Exception as e:
        app_logger.error(f"Error during DB retention cleanup: {e}")
    finally:
        try:
            db.close_session()
        except Exception as e:
            app_logger.error(f"Error closing DB session after retention cleanup: {e}")
