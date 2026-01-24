# tasks/export_malicious_ips.py

import os
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from logger import get_app_logger
from database import get_database
from config import get_config
from models import AccessLog
from ip_utils import is_local_or_private_ip, is_valid_public_ip
from sqlalchemy import distinct

app_logger = get_app_logger()

# ----------------------
# TASK CONFIG
# ----------------------
TASK_CONFIG = {
    "name": "export-malicious-ips",
    "cron": "*/5 * * * *",
    "enabled": True,
    "run_when_loaded": True,
}

EXPORTS_DIR = "exports"
OUTPUT_FILE = os.path.join(EXPORTS_DIR, "malicious_ips.txt")


# ----------------------
# TASK LOGIC
# ----------------------
def has_recent_honeypot_access(session, minutes: int = 5) -> bool:
    """Check if honeypot was accessed in the last N minutes."""
    cutoff_time = datetime.now() - timedelta(minutes=minutes)
    count = (
        session.query(AccessLog)
        .filter(
            AccessLog.is_honeypot_trigger == True, AccessLog.timestamp >= cutoff_time
        )
        .count()
    )
    return count > 0


def main():
    """
    Export all IPs flagged as suspicious to a text file.
    TasksMaster will call this function based on the cron schedule.
    """
    task_name = TASK_CONFIG.get("name")
    app_logger.info(f"[Background Task] {task_name} starting...")

    try:
        db = get_database()
        session = db.session

        # Check for recent honeypot activity
        if not has_recent_honeypot_access(session):
            app_logger.info(
                f"[Background Task] {task_name} skipped - no honeypot access in last 5 minutes"
            )
            return

        # Query distinct suspicious IPs
        results = (
            session.query(distinct(AccessLog.ip))
            .filter(AccessLog.is_suspicious == True)
            .all()
        )

        # Filter out local/private IPs and the server's own IP
        config = get_config()
        server_ip = config.get_server_ip()
        
        public_ips = [
            ip for (ip,) in results
            if is_valid_public_ip(ip, server_ip)
        ]

        # Ensure exports directory exists
        os.makedirs(EXPORTS_DIR, exist_ok=True)

        # Write IPs to file (one per line)
        with open(OUTPUT_FILE, "w") as f:
            for ip in public_ips:
                f.write(f"{ip}\n")

        app_logger.info(
            f"[Background Task] {task_name} exported {len(public_ips)} public IPs "
            f"(filtered {len(results) - len(public_ips)} local/private IPs) to {OUTPUT_FILE}"
        )

    except Exception as e:
        app_logger.error(f"[Background Task] {task_name} failed: {e}")
    finally:
        db.close_session()
