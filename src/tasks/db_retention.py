#!/usr/bin/env python3

"""
Database retention task for Krawl honeypot.
Periodically deletes old records based on configured retention_days.
"""

from datetime import datetime, timedelta

from sqlalchemy import or_

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
    Delete old records based on the configured retention period.
    Keeps suspicious access logs, their attack detections, linked IPs,
    category history, and all credential attempts.
    """
    try:
        from config import get_config
        from models import (
            AccessLog,
            AttackDetection,
            IpStats,
            CategoryHistory,
        )

        config = get_config()
        retention_days = config.database_retention_days

        db = get_database()
        session = db.session

        cutoff = datetime.now() - timedelta(days=retention_days)

        # Delete attack detections linked to old NON-suspicious access logs (FK constraint)
        old_nonsuspicious_log_ids = session.query(AccessLog.id).filter(
            AccessLog.timestamp < cutoff,
            AccessLog.is_suspicious == False,
            AccessLog.is_honeypot_trigger == False,
        )
        detections_deleted = (
            session.query(AttackDetection)
            .filter(AttackDetection.access_log_id.in_(old_nonsuspicious_log_ids))
            .delete(synchronize_session=False)
        )

        # Delete old non-suspicious access logs (keep suspicious ones)
        logs_deleted = (
            session.query(AccessLog)
            .filter(
                AccessLog.timestamp < cutoff,
                AccessLog.is_suspicious == False,
                AccessLog.is_honeypot_trigger == False,
            )
            .delete(synchronize_session=False)
        )

        # IPs to preserve: those with any suspicious access logs
        preserved_ips = (
            session.query(AccessLog.ip)
            .filter(
                or_(
                    AccessLog.is_suspicious == True,
                    AccessLog.is_honeypot_trigger == True,
                )
            )
            .distinct()
        )

        # Delete stale IPs, but keep those linked to suspicious logs
        ips_deleted = (
            session.query(IpStats)
            .filter(
                IpStats.last_seen < cutoff,
                ~IpStats.ip.in_(preserved_ips),
            )
            .delete(synchronize_session=False)
        )

        # Delete old category history, but keep records for preserved IPs
        history_deleted = (
            session.query(CategoryHistory)
            .filter(
                CategoryHistory.timestamp < cutoff,
                ~CategoryHistory.ip.in_(preserved_ips),
            )
            .delete(synchronize_session=False)
        )

        session.commit()

        total = logs_deleted + detections_deleted + ips_deleted + history_deleted
        if total:
            app_logger.info(
                f"DB retention: Deleted {logs_deleted} access logs, "
                f"{detections_deleted} attack detections, "
                f"{ips_deleted} stale IPs, "
                f"{history_deleted} category history records "
                f"older than {retention_days} days"
            )

    except Exception as e:
        app_logger.error(f"Error during DB retention cleanup: {e}")
    finally:
        try:
            db.close_session()
        except Exception as e:
            app_logger.error(f"Error closing DB session after retention cleanup: {e}")
