from banlist_sync import refresh_banlist_sources
from config import get_config
from logger import get_app_logger

TASK_CONFIG = {
    "name": "refresh-banlist",
    "enabled": True,
    "run_when_loaded": True,
    "interval_seconds": 3600,
}


def main():
    config = get_config()
    if not config.banlist_sources:
        get_app_logger().debug(
            "[RefreshBanlist] No banlist sources configured, skipping"
        )
        return

    # Update interval from config in case it changed
    TASK_CONFIG["interval_seconds"] = config.banlist_refresh_interval

    refresh_banlist_sources()
