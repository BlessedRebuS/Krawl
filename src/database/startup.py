"""One-time startup maintenance for the Krawl database.

Runs at boot (idempotent, safe every time). Keeps the database consistent with
rules that were introduced after some data had already been persisted:

- Private/local/reserved IPs should never be tracked, so purge any that
  predate the tracking guard from every IP-bearing table.
- When ``ipv6.purge_existing`` is set, drop the IPv6 rows that accumulated
  before ``ipv6.ignore`` was turned on.
- Fully expired bans should not linger, so clear stale ban state.

Each step is exposed as a standalone function so the dashboard maintenance
panel can run them individually; ``run_startup_cleanup`` is just the boot-time
composition of the three.

Every step logs before it starts, not just after. This routine is the slowest
part of boot on a large database and used to run silently, which read as a hang
right after "Database ready".
"""

import time
from datetime import datetime
from typing import TYPE_CHECKING

from ip_utils import is_ignored_ip
from logger import get_app_logger
from models import (
    AccessLog,
    AttackDetection,
    CategoryHistory,
    CredentialAttempt,
    IpStats,
    TrackedIp,
)

if TYPE_CHECKING:
    from database.core import DatabaseManager

applogger = get_app_logger()

# Chunk size for IN() clauses so we stay under SQLite's ~999-variable limit.
_CHUNK = 500

# Rows deleted per transaction when purging IPv6 in bulk. Keeps the undo log
# bounded on PostgreSQL rather than building one enormous transaction.
_PURGE_BATCH = 10_000

# Rows fetched per round-trip when walking the ip-keyed tables for candidates.
_SCAN_BATCH = 10_000

# Every table that stores a client IP. attack_detections is handled separately:
# it references access_logs by id, not by IP.
_IP_TABLES = (
    (AccessLog, AccessLog.ip),
    (CredentialAttempt, CredentialAttempt.ip),
    (CategoryHistory, CategoryHistory.ip),
    (TrackedIp, TrackedIp.ip),
    (IpStats, IpStats.ip),
)


def purge_ipv6_rows(session) -> int:
    """Delete every IPv6 row, in SQL, batched.

    IPv6 addresses are the only ones containing a colon, so ``LIKE '%:%'``
    identifies them without pulling a single row into Python. That matters:
    purge_ignored_ips below is O(distinct IPs) in memory, and the whole reason
    this purge exists is a flood that produced tens of thousands of them.
    """
    deleted = 0

    # attack_detections has an FK to access_logs with ON DELETE CASCADE, but
    # SQLite does not enforce that unless PRAGMA foreign_keys is on, so clear
    # it explicitly first.
    while True:
        log_ids = [
            r[0]
            for r in session.query(AccessLog.id)
            .filter(AccessLog.ip.like("%:%"))
            .limit(_PURGE_BATCH)
            .all()
        ]
        if not log_ids:
            break
        for start in range(0, len(log_ids), _CHUNK):
            chunk = log_ids[start : start + _CHUNK]
            session.query(AttackDetection).filter(
                AttackDetection.access_log_id.in_(chunk)
            ).delete(synchronize_session=False)
        deleted += (
            session.query(AccessLog)
            .filter(AccessLog.id.in_(log_ids))
            .delete(synchronize_session=False)
        )
        session.commit()
        applogger.info(f"  … purged {deleted} IPv6 access_log row(s) so far")

    for model, column in _IP_TABLES:
        if model is AccessLog:
            continue  # already drained above
        n = (
            session.query(model)
            .filter(column.like("%:%"))
            .delete(synchronize_session=False)
        )
        session.commit()
        if n:
            deleted += n
            applogger.info(f"  … purged {n} IPv6 row(s) from {model.__tablename__}")

    return deleted


def purge_ignored_ips(session, ignored_ips: list[str]) -> int:
    """Delete every row belonging to an IP on the configured ignore list.

    Candidates come only from the tables keyed BY ip — ip_stats and
    tracked_ips, where ip is the primary key — so finding them is an
    index-only walk of the distinct set.

    It used to run `SELECT DISTINCT ip` across all five IP-bearing tables.
    access_logs and category_history hold one row per event, so that scan was
    O(traffic) rather than O(addresses): on an instance under an IPv6proxy
    flood it blocked startup for minutes with no output, which read as a hang
    straight after "Database ready".

    Dropping them loses nothing. An ignored IP is only in the database because
    it was tracked before the ignore guard existed, and tracking has always
    written an ip_stats row in the same transaction as the access_logs row —
    so an ignored IP present in an event table but absent from ip_stats cannot
    occur. The event tables are still *deleted* from below, by their ip index.

    ``ignore_ipv6=False`` keeps this on the explicit list only. The IPv6 policy
    is a separate opt-in (purge_ipv6_rows); letting it leak in here would
    delete all IPv6 history the moment ``ipv6.ignore`` was enabled.
    """
    matched_ips: set[str] = set()
    for col in (IpStats.ip, TrackedIp.ip):
        # No .distinct(): both columns are primary keys. yield_per streams the
        # rows instead of materialising every address at once — this runs at
        # boot, on the machine whose memory we are trying to keep down.
        for (ip,) in session.query(col).yield_per(_SCAN_BATCH):
            if ip and is_ignored_ip(ip, ignored_ips, ignore_ipv6=False):
                matched_ips.add(ip)

    if not matched_ips:
        return 0

    ip_list = list(matched_ips)
    for start in range(0, len(ip_list), _CHUNK):
        chunk = ip_list[start : start + _CHUNK]
        log_ids = [
            r[0]
            for r in session.query(AccessLog.id).filter(AccessLog.ip.in_(chunk)).all()
        ]
        for lstart in range(0, len(log_ids), _CHUNK):
            lchunk = log_ids[lstart : lstart + _CHUNK]
            session.query(AttackDetection).filter(
                AttackDetection.access_log_id.in_(lchunk)
            ).delete(synchronize_session=False)
        for model, column in _IP_TABLES:
            session.query(model).filter(column.in_(chunk)).delete(
                synchronize_session=False
            )
    return len(matched_ips)


def clear_expired_bans(session, ban_duration_seconds: int) -> int:
    """Release bans whose window has fully elapsed.

    The window is per-row (ban_multiplier varies), so it is computed in Python
    rather than as a single SQL predicate.
    """
    cleared = 0
    now = datetime.now()
    for row in session.query(IpStats).filter(IpStats.ban_timestamp.isnot(None)).all():
        effective = ban_duration_seconds * (row.ban_multiplier or 1)
        if (now - row.ban_timestamp).total_seconds() > effective:
            row.ban_timestamp = None
            row.page_visit_count = 0
            cleared += 1
    return cleared


def run_startup_cleanup(
    db: "DatabaseManager",
    ban_duration_seconds: int,
    ignored_ips: list[str],
    purge_ipv6: bool = False,
) -> dict[str, int]:
    """Purge ignored IPs and clear expired bans. Returns a summary of counts.

    ``ignored_ips`` is the configured list of IPs/CIDRs to purge (see
    config.Config.ignored_ips). ``purge_ipv6`` additionally drops every IPv6
    row (see config.Config.ipv6_purge_existing); it is deliberately separate
    from ``ipv6.ignore`` so that turning the flood guard on does not silently
    delete existing history.
    """
    session = db.session
    summary = {"ignored_ips": 0, "ipv6_purged": 0, "expired_bans_cleared": 0}
    try:
        # IPv6 purge first, so the ignore-list scan below has less to walk.
        if purge_ipv6:
            applogger.info("Startup cleanup: purging existing IPv6 rows…")
            t0 = time.monotonic()
            summary["ipv6_purged"] = purge_ipv6_rows(session)
            applogger.info(
                f"Startup cleanup: purged {summary['ipv6_purged']} IPv6 row(s) "
                f"in {time.monotonic() - t0:.1f}s"
            )

        applogger.info("Startup cleanup: scanning for ignored IPs…")
        t0 = time.monotonic()
        summary["ignored_ips"] = purge_ignored_ips(session, ignored_ips)
        applogger.info(
            f"Startup cleanup: removed {summary['ignored_ips']} ignored IP(s) "
            f"in {time.monotonic() - t0:.1f}s"
        )

        applogger.info("Startup cleanup: clearing expired bans…")
        summary["expired_bans_cleared"] = clear_expired_bans(
            session, ban_duration_seconds
        )

        session.commit()
        applogger.info(
            f"Startup cleanup done: removed {summary['ignored_ips']} ignored IP(s), "
            f"purged {summary['ipv6_purged']} IPv6 row(s), "
            f"cleared {summary['expired_bans_cleared']} expired ban(s)"
        )
        return summary
    except Exception as e:
        session.rollback()
        applogger.error(f"Startup cleanup failed: {e}")
        return summary
    finally:
        db.close_session()
