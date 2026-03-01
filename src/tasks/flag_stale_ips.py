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

# Set to True to force all IPs to be flagged for reevaluation on next run.
# Resets to False automatically after execution.
FORCE_IP_RESCAN = False


def main():
    global FORCE_IP_RESCAN

    app_logger = get_app_logger()
    db = get_database()

    try:
        if FORCE_IP_RESCAN:
            count = db.flag_all_ips_for_reevaluation()
            FORCE_IP_RESCAN = False
            app_logger.info(
                f"[Background Task] flag-stale-ips: FORCE RESCAN - Flagged {count} IPs for reevaluation"
            )
        else:
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
