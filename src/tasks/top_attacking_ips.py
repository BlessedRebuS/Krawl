# tasks/export_malicious_ips.py

import os
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from logger import get_app_logger
from database import get_database
from config import get_config
from models import AccessLog, IpStats
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
    Export all attacker IPs to a text file, matching the "Attackers by Total Requests" dashboard table.
    Uses the same query as the dashboard: IpStats where category == "attacker", ordered by total_requests.
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

        # Query attacker IPs from IpStats (same as dashboard "Attackers by Total Requests")
        attackers = (
            session.query(IpStats)
            .filter(IpStats.category == "attacker")
            .order_by(IpStats.total_requests.desc())
            .all()
        )

        # Filter out local/private IPs and the server's own IP
        config = get_config()
        server_ip = config.get_server_ip()
        
        public_ips = [
            attacker.ip for attacker in attackers
            if is_valid_public_ip(attacker.ip, server_ip)
        ]

        # Ensure exports directory exists
        os.makedirs(EXPORTS_DIR, exist_ok=True)

        # Write IPs to file (one per line)
        with open(OUTPUT_FILE, "w") as f:
            for ip in public_ips:
                f.write(f"{ip}\n")

        app_logger.info(
            f"[Background Task] {task_name} exported {len(public_ips)} attacker IPs "
            f"(filtered {len(attackers) - len(public_ips)} local/private IPs) to {OUTPUT_FILE}"
        )

    except Exception as e:
        app_logger.error(f"[Background Task] {task_name} failed: {e}")
    finally:
        db.close_session()
