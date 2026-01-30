# tasks/export_malicious_ips.py

import os
from logger import get_app_logger
from database import get_database
from config import get_config
from models import IpStats, AccessLog
from ip_utils import is_valid_public_ip
from sqlalchemy import distinct
from firewall.fwtype import FWType
from firewall.iptables import Iptables
from firewall.raw import Raw

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

EXPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "exports")
OUTPUT_FILE = os.path.join(EXPORTS_DIR, "malicious_ips.txt")


# ----------------------
# TASK LOGIC
# ----------------------
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
            attacker.ip
            for attacker in attackers
            if is_valid_public_ip(attacker.ip, server_ip)
        ]

        # Ensure exports directory exists
        os.makedirs(EXPORTS_DIR, exist_ok=True)

        # Write IPs to file (one per line)
        for fwname in FWType._registry:

            # get banlist for specific ip
            fw = FWType.create(fwname)
            banlist = fw.getBanlist(public_ips)

            output_file = os.path.join(EXPORTS_DIR, f"{fwname}.txt")
            with open(output_file, "w") as f:
                f.write(f"{banlist}\n")

                app_logger.info(
                    f"[Background Task] {task_name} exported {len(public_ips)} in {fwname} public IPs"
                    f"(filtered {len(attackers) - len(public_ips)} local/private IPs) to {output_file}"
                )

    except Exception as e:
        app_logger.error(f"[Background Task] {task_name} failed: {e}")
    finally:
        db.close_session()
