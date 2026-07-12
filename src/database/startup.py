"""One-time startup maintenance for the Krawl database.

Runs at boot (idempotent, safe every time). Keeps the database consistent with
rules that were introduced after some data had already been persisted:

- Private/local/reserved IPs should never be tracked, so purge any that
  predate the tracking guard from every IP-bearing table.
- Fully expired bans should not linger, so clear stale ban state.
"""

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


def run_startup_cleanup(
    db: "DatabaseManager", ban_duration_seconds: int, ignored_ips: list[str]
) -> dict[str, int]:
    """Purge ignored IPs and clear expired bans. Returns a summary of counts.

    ``ignored_ips`` is the configured list of IPs/CIDRs to purge (see
    config.Config.ignored_ips).
    """
    session = db.session
    summary = {"ignored_ips": 0, "expired_bans_cleared": 0}
    try:
        # 1. Collect distinct ignored IPs (per the configured list) across
        #    all IP-bearing tables.
        matched_ips: set[str] = set()
        for col in (
            IpStats.ip,
            AccessLog.ip,
            CredentialAttempt.ip,
            CategoryHistory.ip,
            TrackedIp.ip,
        ):
            for (ip,) in session.query(col).distinct():
                if ip and is_ignored_ip(ip, ignored_ips):
                    matched_ips.add(ip)

        # 2. Delete rows for those IPs. attack_detections has an FK to
        #    access_logs with ON DELETE CASCADE, but SQLite does not enforce
        #    that unless PRAGMA foreign_keys is on, so delete it explicitly
        #    first. Chunk the IN() lists to stay under SQLite's variable cap.
        if matched_ips:
            ip_list = list(matched_ips)
            for start in range(0, len(ip_list), _CHUNK):
                chunk = ip_list[start : start + _CHUNK]
                log_ids = [
                    r[0]
                    for r in session.query(AccessLog.id)
                    .filter(AccessLog.ip.in_(chunk))
                    .all()
                ]
                for lstart in range(0, len(log_ids), _CHUNK):
                    lchunk = log_ids[lstart : lstart + _CHUNK]
                    session.query(AttackDetection).filter(
                        AttackDetection.access_log_id.in_(lchunk)
                    ).delete(synchronize_session=False)
                for model, column in (
                    (AccessLog, AccessLog.ip),
                    (CredentialAttempt, CredentialAttempt.ip),
                    (CategoryHistory, CategoryHistory.ip),
                    (TrackedIp, TrackedIp.ip),
                    (IpStats, IpStats.ip),
                ):
                    session.query(model).filter(column.in_(chunk)).delete(
                        synchronize_session=False
                    )
            summary["ignored_ips"] = len(matched_ips)

        # 3. Clear expired bans for the remaining (public) IPs. The ban window
        #    is per-row (ban_multiplier varies), so compute it in Python.
        now = datetime.now()
        banned = session.query(IpStats).filter(IpStats.ban_timestamp.isnot(None)).all()
        for row in banned:
            multiplier = row.ban_multiplier or 1
            effective = ban_duration_seconds * multiplier
            elapsed = (now - row.ban_timestamp).total_seconds()
            if elapsed > effective:
                row.ban_timestamp = None
                row.page_visit_count = 0
                summary["expired_bans_cleared"] += 1

        session.commit()
        if summary["ignored_ips"] or summary["expired_bans_cleared"]:
            applogger.info(
                f"Startup cleanup: removed {summary['ignored_ips']} ignored IP(s), "
                f"cleared {summary['expired_bans_cleared']} expired ban(s)"
            )
        return summary
    except Exception as e:
        session.rollback()
        applogger.error(f"Startup cleanup failed: {e}")
        return summary
    finally:
        db.close_session()
