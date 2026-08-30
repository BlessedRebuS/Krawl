from datetime import UTC

from logger import get_app_logger

TASK_CONFIG = {
    "name": "sync-cloudflare",
    "enabled": True,
    # pushes again 60 seconds later regardless.
    "run_when_loaded": False,
    "interval_seconds": 60,
}


def main():
    """Sync the banlist to CloudFlare. Called by APScheduler every interval_seconds."""
    try:
        from webhooks import (
            get_cloudflare_config,
            save_cloudflare_config,
            sync_banlist_to_cloudflare,
        )

        cf_config = get_cloudflare_config()

        if not cf_config.get("enabled") or not cf_config.get("account_id"):
            return

        from datetime import datetime

        result = sync_banlist_to_cloudflare(cf_config)

        # Update last_sync in config
        cf_config["last_sync"] = datetime.now(UTC).isoformat()
        cf_config["last_sync_status"] = result.get("status", "error")
        cf_config["last_sync_error"] = result.get("error")
        save_cloudflare_config(cf_config)

        if result.get("status") == "ok":
            get_app_logger().info(f"[CF Sync] Synced {result.get('count', 0)} IPs")
        else:
            get_app_logger().warning(
                f"[CF Sync] Sync failed: {result.get('error', 'unknown')}"
            )

    except Exception as e:
        get_app_logger().error(f"[CF Sync] Task error: {e}")
