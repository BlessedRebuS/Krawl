# tasks/db_cleanup.py

from config import get_config
from database import get_database
from database.startup import run_startup_cleanup
from logger import get_app_logger

# ----------------------
# TASK CONFIG
# ----------------------
TASK_CONFIG = {
    "name": "db-cleanup",
    "cron": "0 3 * * *",  # Nightly at 03:00, off the boot path
    "enabled": True,
    "run_when_loaded": False,
    "single_pod": True,
}


def main():
    config = get_config()
    try:
        run_startup_cleanup(
            get_database(),
            config.ban_duration_seconds,
            config.ignored_ips,
            purge_ipv6=config.ipv6_ignore and config.ipv6_purge_existing,
        )
    except Exception as e:
        get_app_logger().error(f"[Background Task] db-cleanup failed: {e}")
