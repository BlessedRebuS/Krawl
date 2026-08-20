#!/usr/bin/env python3

"""
Database retention task for Krawl honeypot.
Periodically deletes old records based on configured retention_days.
"""

from datetime import datetime, timedelta

from sqlalchemy import delete as sa_delete
from sqlalchemy import or_

from dashboard_cache import invalidate_table_cache
from database import get_database
from logger import get_app_logger

# ----------------------
# TASK CONFIG
# ----------------------

# Rows per delete transaction; the first run after the is_(False) fix has a
# large backlog to clear.
DELETE_BATCH_SIZE = 10_000

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
            CategoryHistory,
            IpStats,
            MetricsSummary,
        )

        config = get_config()
        retention_days = config.database_retention_days

        db = get_database()
        session = db.session

        cutoff = datetime.now() - timedelta(days=retention_days)

        # `not <column>` is Python truthiness, not SQL NOT: it collapses to the
        # literal False and the whole predicate becomes "AND false", so these
        # two deletes matched nothing. Use is_(False) — NULL-safe and explicit.
        purgeable = (
            AccessLog.timestamp < cutoff,
            AccessLog.is_suspicious.is_(False),
            AccessLog.is_honeypot_trigger.is_(False),
        )

        # Delete in batches: the first run after this fix has a large backlog to
        # clear, and one statement over millions of rows is a long lock and a
        # large WAL write.
        detections_deleted = 0
        logs_deleted = 0
        while True:
            batch_ids = [
                row[0]
                for row in session.query(AccessLog.id)
                .filter(*purgeable)
                .limit(DELETE_BATCH_SIZE)
                .all()
            ]
            if not batch_ids:
                break

            detections_deleted += (
                session.query(AttackDetection)
                .filter(AttackDetection.access_log_id.in_(batch_ids))
                .delete(synchronize_session=False)
            )
            logs_deleted += (
                session.query(AccessLog)
                .filter(AccessLog.id.in_(batch_ids))
                .delete(synchronize_session=False)
            )
            session.commit()

        # IPs to preserve: those with any suspicious access logs
        preserved_ips = (
            session.query(AccessLog.ip)
            .filter(
                or_(
                    AccessLog.is_suspicious,
                    AccessLog.is_honeypot_trigger,
                )
            )
            .distinct()
        )

        # Delete stale IPs, but keep those linked to suspicious logs.
        # Use RETURNING so we tally exactly the rows THIS run deleted — under
        # per-pod scheduling the second pod deletes 0 rows and tallies nothing,
        # keeping the cumulative counts correct without cross-pod coordination.
        deleted_rows = session.execute(
            sa_delete(IpStats)
            .where(
                IpStats.last_seen < cutoff,
                ~IpStats.ip.in_(preserved_ips),
            )
            .returning(IpStats.total_requests)
        ).fetchall()
        ips_deleted = len(deleted_rows)
        deleted_accesses = sum(int(r[0] or 0) for r in deleted_rows)

        # Accumulate what we removed into the cumulative "deleted" tallies, so
        # reconciliation keeps total_accesses / unique_ips absolute (total-ever,
        # not just retained rows): reconciled = count(current rows) + tally.
        if ips_deleted:
            _bump_deleted_tally(session, MetricsSummary, "unique_ips", ips_deleted)
            _bump_deleted_tally(
                session, MetricsSummary, "total_accesses", deleted_accesses
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
            # Invalidate cached dashboard tables so stale deleted data isn't served
            invalidate_table_cache()
            app_logger.info(
                f"DB retention: Deleted {logs_deleted} access logs, "
                f"{detections_deleted} attack detections, "
                f"{ips_deleted} stale IPs, "
                f"{history_deleted} category history records "
                f"older than {retention_days} days"
            )

        # Recompute cumulative counters from (current rows + deleted tallies) now
        # that data was purged. Lock-guarded so only one pod runs the scan.
        try:
            import metrics_counters

            metrics_counters.reconcile(db)
        except Exception as e:
            app_logger.error(f"Error reconciling metrics after retention: {e}")

    except Exception as e:
        app_logger.error(f"Error during DB retention cleanup: {e}")
    finally:
        try:
            db.close_session()
        except Exception as e:
            app_logger.error(f"Error closing DB session after retention cleanup: {e}")


def _bump_deleted_tally(session, MetricsSummary, metric: str, amount: int) -> None:
    """Add `amount` to the cumulative (metric, '_deleted') tally row in-session.

    Runs inside the retention transaction so the tally and the deletes commit
    atomically.
    """
    if amount <= 0:
        return
    row = (
        session.query(MetricsSummary)
        .filter(MetricsSummary.metric == metric, MetricsSummary.label == "_deleted")
        .first()
    )
    if row:
        row.value = int(row.value) + int(amount)
        row.updated_at = datetime.now()
    else:
        session.add(
            MetricsSummary(
                metric=metric,
                label="_deleted",
                value=int(amount),
                updated_at=datetime.now(),
            )
        )
