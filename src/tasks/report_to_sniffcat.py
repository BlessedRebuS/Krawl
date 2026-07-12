from datetime import datetime

from config import get_config
from database import get_database
from logger import get_app_logger
from sniffcat_reporter import report_ip

TASK_CONFIG = {
    "name": "sniffcat-report",
    "cron": "*/5 * * * *",
    "enabled": True,
    "run_when_loaded": False,
}


def main():
    config = get_config()
    app_logger = get_app_logger()

    if not config.sniffcat_enabled:
        return

    if not config.sniffcat_api_key:
        app_logger.warning("SniffCat reporting is enabled but no API key is configured")
        return

    db_manager = get_database()

    ips_to_report = db_manager.ip_stats.get_ips_for_sniffcat_report(
        interval_minutes=20
    )
    if not ips_to_report:
        return

    app_logger.info(f"Found {len(ips_to_report)} IP(s) to report to SniffCat")

    for ip_data in ips_to_report:
        ip = ip_data["ip"]
        category = ip_data["category"]

        try:
            access_logs = db_manager.access_logs.get_list(
                limit=1, ip_filter=ip
            )
            access_log = access_logs[0] if access_logs else None

            success = report_ip(ip, category, access_log=access_log)
            if success:
                db_manager.ip_stats.mark_sniffcat_reported(
                    ip, reported_at=datetime.now()
                )
            else:
                app_logger.warning(
                    f"Failed to report {ip} ({category}) to SniffCat, will retry next cycle"
                )
        except Exception as e:
            app_logger.error(f"Error processing IP {ip} for SniffCat report: {e}")
