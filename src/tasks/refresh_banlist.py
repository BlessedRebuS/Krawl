from banlist_sync import load_published, refresh_banlist_sources
from config import get_config
from logger import get_app_logger

TASK_CONFIG = {
    "name": "refresh-banlist",
    "enabled": True,
    # the lifespan already does an initial banlist sync before traffic is accepted; this repeated it.
    "run_when_loaded": False,
    "interval_seconds": 3600,
    # One pod fetches the external sources; the rest adopt what it published via
    # on_skip() below. Not gated by single_pod alone: the list lives in a
    # per-pod frozenset, so a follower that merely skipped would go stale.
    "single_pod": True,
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


def on_skip() -> None:
    """Another pod owns this refresh; adopt its result rather than go stale.

    The global banlist is a process-local frozenset read by the ban-check
    middleware on every request. Skipping without adopting would leave this pod
    enforcing an ever-older list.
    """
    if not get_config().banlist_sources:
        return

    if not load_published():
        get_app_logger().debug(
            "[RefreshBanlist] Nothing published yet; keeping the current list"
        )
