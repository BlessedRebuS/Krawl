#!/usr/bin/env python3

"""
Delete uninteresting access logs (random-path crawler GETs) after
retention.uninteresting, and count them per IP so analyze-ips can keep its
ratios. See docs/algorithms.md.
"""

from collections import Counter, defaultdict
from datetime import datetime, timedelta

from sqlalchemy import DateTime, case, literal, or_, update

from config import ANALYZER_LOOKBACK_DAYS, get_config
from dashboard_cache import invalidate_table_cache
from database import get_database
from database.maintenance import advisory_lock
from logger import get_app_logger

TASK_CONFIG = {
    "name": "prune-uninteresting",
    "cron": "0 */4 * * *",
    "enabled": True,
    "run_when_loaded": False,
    # The lease can expire before a slow run ends, so main() also takes a lock.
    "single_pod": True,
}

# Pruning removes only non-suspicious rows, so the warmed Attacks tab survives it.
PRUNE_SAFE_KEYS = (
    "attacks:",
    "attackers:",
    "api:attack_",
    "credentials:",
    "honeypot:",
    "domains:rollup",
)
_PRUNE_LOCK = 0x4B52_5052

app_logger = get_app_logger()


def _bump_counters(session, counts: Counter, now: datetime) -> None:
    """Add each IP's pruned rows, restarting pruned_requests once it has expired."""
    from models import IpStats

    stale = or_(
        IpStats.pruned_since.is_(None),
        IpStats.pruned_since < now - timedelta(days=ANALYZER_LOOKBACK_DAYS),
    )
    # Most IPs share a small count, so grouping keeps this to a few statements.
    by_count = defaultdict(list)
    for ip, n in counts.items():
        by_count[n].append(ip)
    for n, ips in sorted(by_count.items()):
        session.execute(
            update(IpStats)
            .where(IpStats.ip.in_(sorted(ips)))
            .values(
                pruned_total=IpStats.pruned_total + n,
                pruned_requests=case((stale, n), else_=IpStats.pruned_requests + n),
                pruned_since=case(
                    (stale, literal(now, DateTime)), else_=IpStats.pruned_since
                ),
            )
            .execution_options(synchronize_session=False)
        )


def _prune_batch(session, cutoff: datetime, batch: int, now: datetime) -> int:
    """Delete one batch and its counters in one transaction. Returns rows deleted."""
    from models import AccessLog, AttackDetection, RequestAsset

    rows = (
        session.query(AccessLog.id, AccessLog.ip)
        .filter(
            AccessLog.is_interesting == False,  # noqa: E712 (matches the partial index)
            AccessLog.is_suspicious.is_(False),
            AccessLog.is_honeypot_trigger.is_(False),
            AccessLog.timestamp < cutoff,
        )
        .limit(batch)
        .all()
    )
    if not rows:
        return 0
    ids = [row.id for row in rows]
    session.query(AttackDetection).filter(
        AttackDetection.access_log_id.in_(ids)
    ).delete(synchronize_session=False)
    session.query(RequestAsset).filter(RequestAsset.access_log_id.in_(ids)).delete(
        synchronize_session=False
    )
    session.query(AccessLog).filter(AccessLog.id.in_(ids)).delete(
        synchronize_session=False
    )
    _bump_counters(session, Counter(row.ip for row in rows), now)
    session.commit()
    return len(ids)


def _prune() -> None:
    config = get_config()
    db = get_database()
    session = db.session
    now = datetime.now()
    cutoff = now - config.retention_uninteresting
    deleted = 0
    try:
        while True:
            pruned = _prune_batch(
                session, cutoff, config.tasks_retention_delete_batch, now
            )
            if not pruned:
                break
            deleted += pruned
    except Exception as e:
        # Rows and counters roll back together, so the next run retries safely.
        session.rollback()
        app_logger.error(f"prune-uninteresting: batch failed: {e}")
    finally:
        db.close_session()
    if deleted:
        invalidate_table_cache(keep=PRUNE_SAFE_KEYS)
        app_logger.info(f"prune-uninteresting: {deleted} rows deleted")


def main():
    with advisory_lock(get_database().engine, _PRUNE_LOCK) as held:
        if held:
            _prune()
        else:
            app_logger.info("prune-uninteresting: previous run still going; skipping")
