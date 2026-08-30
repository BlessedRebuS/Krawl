"""On-demand database purge, driven from the dashboard maintenance panel.

Never scheduled (``enabled: False``) — it exists so the panel can run the same
cleanup steps that boot runs, selectively, without duplicating their SQL. Each
target maps to a function in database.startup.
"""

from database import get_database
from database.startup import clear_expired_bans, purge_ignored_ips, purge_ipv6_rows
from logger import get_app_logger

app_logger = get_app_logger()

TASK_CONFIG = {
    "name": "purge",
    "enabled": False,
    "run_when_loaded": False,
}

# target -> (label for the UI, summary key)
PURGE_TARGETS = {
    "ipv6": "Delete all IPv6 rows",
    "ignored_ips": "Delete rows for IPs on the ignore list",
    "expired_bans": "Release bans whose window has elapsed",
}


def main(targets: list[str] | None = None) -> dict[str, int]:
    """Run the selected purge targets. Returns per-target row counts.

    With no targets this is a no-op rather than a full purge: an accidental
    empty selection should never delete anything.
    """
    from config import get_config

    targets = [t for t in (targets or []) if t in PURGE_TARGETS]
    summary = {t: 0 for t in targets}
    if not targets:
        return summary

    config = get_config()
    db = get_database()
    session = db.session
    try:
        if "ipv6" in targets:
            summary["ipv6"] = purge_ipv6_rows(session)
        if "ignored_ips" in targets:
            summary["ignored_ips"] = purge_ignored_ips(session, config.ignored_ips)
        if "expired_bans" in targets:
            summary["expired_bans"] = clear_expired_bans(
                session, config.ban_duration_seconds
            )
        session.commit()
        app_logger.info(f"Manual purge complete: {summary}")
        return summary
    except Exception as e:
        session.rollback()
        app_logger.error(f"Manual purge failed: {e}")
        raise
    finally:
        db.close_session()
