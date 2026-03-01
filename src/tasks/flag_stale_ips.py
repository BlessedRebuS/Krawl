from database import get_database
from logger import get_app_logger

# ----------------------
# TASK CONFIG
# ----------------------

TASK_CONFIG = {
    "name": "flag-stale-ips",
    "cron": "0 2 * * *",  # Run daily at 2 AM
    "enabled": True,
    "run_when_loaded": True,
}


def main():
    app_logger = get_app_logger()
    db = get_database()

    try:
        count = db.flag_stale_ips_for_reevaluation()
        if count > 0:
            app_logger.info(
                f"[Background Task] flag-stale-ips: Flagged {count} stale IPs for reevaluation"
            )
        else:
            app_logger.debug(
                "[Background Task] flag-stale-ips: No stale IPs found to flag"
            )
    except Exception as e:
        app_logger.error(
            f"[Background Task] flag-stale-ips: Error flagging stale IPs: {e}"
        )
