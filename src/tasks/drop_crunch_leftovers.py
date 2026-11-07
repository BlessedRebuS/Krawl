#!/usr/bin/env python3

"""One-off: delete the rows the removed crunch job merged, then drop its columns."""

from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import inspect, text

from config import get_config
from dashboard_cache import invalidate_table_cache
from database import get_database
from database.maintenance import advisory_lock
from logger import get_app_logger
from models import MetricsSummary
from tasks.prune_uninteresting import PRUNE_SAFE_KEYS, delete_counted

TASK_CONFIG = {
    "name": "drop-crunch-leftovers",
    "cron": "47 * * * *",
    "enabled": True,
    "run_when_loaded": True,
    "single_pod": True,
}

COLUMNS = (
    ("access_logs", "hit_count"),
    ("access_logs", "path_samples"),
    ("ip_stats", "crunched_at"),
)
# Old pods select these columns until a rolling update ends.
DROP_DELAY = timedelta(hours=1)
_MARKER = ("crunch_cleanup", "started")
_LOCK = 0x4B52_4443

app_logger = get_app_logger()


def _leftovers(engine) -> list[tuple[str, str]]:
    insp = inspect(engine)
    found = {t: {c["name"] for c in insp.get_columns(t)} for t, _ in COLUMNS}
    return [(t, c) for t, c in COLUMNS if c in found[t]]


def _delete_crunched(session, batch: int, now: datetime) -> int:
    """Delete merged rows, counting their requests as pruned so analyzer ratios hold."""
    # ponytail: one full scan with all ids in memory; fine for a one-off.
    rows = session.execute(
        text("SELECT id, ip, hit_count FROM access_logs WHERE hit_count > 1")
    ).all()
    for start in range(0, len(rows), batch):
        chunk = rows[start : start + batch]
        counts = Counter()
        for row in chunk:
            counts[row.ip] += row.hit_count
        delete_counted(session, [row.id for row in chunk], counts, now)
    return len(rows)


def _drop(engine, left: list[tuple[str, str]]) -> None:
    for table, column in left:
        try:
            with engine.begin() as conn:
                # Never queue behind a slow read: writes would queue behind this.
                if engine.dialect.name == "postgresql":
                    conn.execute(text("SET LOCAL lock_timeout = '5s'"))
                conn.execute(text(f"ALTER TABLE {table} DROP COLUMN {column}"))
            app_logger.info(f"drop-crunch-leftovers: dropped {table}.{column}")
        except Exception as e:
            app_logger.error(f"drop-crunch-leftovers: {table}.{column}: {e}")


def main():
    db = get_database()
    engine = db.engine
    with advisory_lock(engine, _LOCK) as held:
        if not held:
            return
        left = _leftovers(engine)
        if not left:
            return
        session = db.session
        now = datetime.now()
        try:
            if ("access_logs", "hit_count") in left:
                deleted = _delete_crunched(
                    session, get_config().tasks_retention_delete_batch, now
                )
                if deleted:
                    invalidate_table_cache(keep=PRUNE_SAFE_KEYS)
                    app_logger.info(f"drop-crunch-leftovers: {deleted} rows deleted")
            marker = session.get(MetricsSummary, _MARKER)
            if marker is None:
                session.add(
                    MetricsSummary(
                        metric=_MARKER[0], label=_MARKER[1], value=0, updated_at=now
                    )
                )
                session.commit()
                return
            if now - marker.updated_at < DROP_DELAY:
                return
            session.rollback()  # release the read before ALTER TABLE takes its lock
            _drop(engine, left)
            if not _leftovers(engine):
                session.query(MetricsSummary).filter(
                    MetricsSummary.metric == _MARKER[0]
                ).delete(synchronize_session=False)
                session.commit()
        except Exception as e:
            # Each batch commits on its own, so the next run resumes safely.
            session.rollback()
            app_logger.error(f"drop-crunch-leftovers failed: {e}")
        finally:
            db.close_session()
