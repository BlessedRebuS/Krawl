#!/usr/bin/env python3

"""
Pre-retention cleanup task for Krawl honeypot.
Runs before the db-retention task to re-check old access logs that were
initially flagged as suspicious. Re-runs the same detection checks
(attack patterns, suspicious user agent, honeypot path) and only unflags
logs that no longer match any rule, so the retention job can purge them.
"""

import re
from datetime import datetime, timedelta

from database import get_database
from wordlists import get_wordlists
from logger import get_app_logger

# ----------------------
# TASK CONFIG
# ----------------------

TASK_CONFIG = {
    "name": "pre-retention-cleanup",
    "cron": "30 2 * * *",  # Run daily at 2:30 AM (before db-retention at 3 AM)
    "enabled": True,
    "run_when_loaded": True,
}

# Batch size for processing old logs to limit memory usage
BATCH_SIZE = 1000

app_logger = get_app_logger()


# ----------------------
# Same detection logic used by the tracker at request time
# ----------------------

HONEYPOT_SUBSTRINGS = [
    "/backup",
    "/admin",
    "/config",
    "/private",
    "/database",
    "phpmyadmin",
]

HONEYPOT_PATHS = {
    "/admin",
    "/admin/",
    "/backup",
    "/backup/",
    "/config",
    "/config/",
    "/private",
    "/private/",
    "/database",
    "/database/",
    "/credentials.txt",
    "/passwords.txt",
    "/admin_notes.txt",
    "/api_keys.json",
    "/.env",
    "/wp-admin",
    "/wp-admin/",
    "/phpmyadmin",
    "/phpMyAdmin/",
}

FALLBACK_SUSPICIOUS_PATTERNS = [
    "bot",
    "crawler",
    "spider",
    "scraper",
    "curl",
    "wget",
    "python-requests",
    "scanner",
    "nikto",
    "sqlmap",
    "nmap",
    "masscan",
    "nessus",
    "acunetix",
    "burp",
    "zap",
    "w3af",
    "metasploit",
    "nuclei",
    "gobuster",
    "dirbuster",
]

FALLBACK_ATTACK_PATTERNS = {
    "path_traversal": r"\.\.",
    "sql_injection": r"('|--|;|\bOR\b|\bUNION\b|\bSELECT\b|\bDROP\b)",
    "xss_attempt": r"(<script|javascript:|onerror=|onload=)",
    "common_probes": r"(/admin|/backup|/config|/database|/private|/uploads|/wp-admin|/login|/phpMyAdmin|/phpmyadmin|/users|/search|/contact|/info|/input|/feedback|/server|/api/v1/|/api/v2/|/api/search|/api/sql|/api/database|\.env|/credentials\.txt|/passwords\.txt|\.git|/backup\.sql|/db_backup\.sql)",
    "login_attempt": r"(/wp-login\.php|/wp-login|/admin/login|/admin/signin|/user/login|/users/login|/account/login|/portal/login|/secure/login|/login\.php|/login\.asp|/login\.aspx|/signin|/sign-in|/sign_in|/auth/login|/api/auth|/api/login|/api/signin|/api/token|/oauth/login|/sso/login|/xmlrpc\.php|/session/new|action=login)",
    "command_injection": r"(\||;|`|\$\(|&&)",
}


def _is_honeypot_path(path: str) -> bool:
    if path in HONEYPOT_PATHS:
        return True
    lower = path.lower()
    return any(hp in lower for hp in HONEYPOT_SUBSTRINGS)


def _is_still_suspicious(
    path: str, user_agent: str, attack_patterns: dict, suspicious_patterns: list
) -> bool:
    """Re-run the same checks the tracker uses at request time."""
    # Honeypot path check
    if _is_honeypot_path(path):
        return True

    # Attack pattern check on path
    for pattern in attack_patterns.values():
        if re.search(pattern, path, re.IGNORECASE):
            return True

    # Suspicious user agent check
    if not user_agent:
        return True
    ua_lower = user_agent.lower()
    if any(p in ua_lower for p in suspicious_patterns):
        return True

    return False


def main():
    """
    Re-check old suspicious access logs past the retention period.
    Unflag only those that no longer match any suspicious rule.
    """
    try:
        from config import get_config
        from models import AccessLog

        config = get_config()
        retention_days = config.database_retention_days

        db = get_database()
        session = db.session

        cutoff = datetime.now() - timedelta(days=retention_days)

        # Load detection rules (same sources as the tracker)
        wl = get_wordlists()
        attack_patterns = wl.attack_patterns or FALLBACK_ATTACK_PATTERNS
        suspicious_patterns = wl.suspicious_patterns or FALLBACK_SUSPICIOUS_PATTERNS

        unflagged = 0
        kept = 0

        # Process in batches to avoid loading everything into memory
        while True:
            old_logs = (
                session.query(AccessLog)
                .filter(
                    AccessLog.timestamp < cutoff,
                    AccessLog.is_suspicious == True,
                    AccessLog.is_honeypot_trigger == False,
                )
                .limit(BATCH_SIZE)
                .all()
            )

            if not old_logs:
                break

            ids_to_unflag = []
            for log in old_logs:
                if _is_still_suspicious(
                    log.path,
                    log.user_agent or "",
                    attack_patterns,
                    suspicious_patterns,
                ):
                    kept += 1
                else:
                    ids_to_unflag.append(log.id)

            if ids_to_unflag:
                (
                    session.query(AccessLog)
                    .filter(AccessLog.id.in_(ids_to_unflag))
                    .update(
                        {AccessLog.is_suspicious: False},
                        synchronize_session=False,
                    )
                )
                unflagged += len(ids_to_unflag)

            # Logs that are still suspicious won't be picked up again
            # because we only unflag the non-suspicious ones, and the
            # still-suspicious ones keep is_suspicious=True.
            # If all logs in the batch were kept, we need to offset past them.
            if not ids_to_unflag:
                # All logs in this batch are still suspicious — no more to process
                break

            session.commit()

        session.commit()

        if unflagged or kept:
            app_logger.info(
                f"[Background Task] pre-retention-cleanup: "
                f"Unflagged {unflagged}, kept {kept} suspicious logs "
                f"(older than {retention_days} days)"
            )
        else:
            app_logger.debug(
                "[Background Task] pre-retention-cleanup: No old suspicious logs found"
            )

    except Exception as e:
        app_logger.error(f"[Background Task] pre-retention-cleanup: Error: {e}")
    finally:
        try:
            db.close_session()
        except Exception as e:
            app_logger.error(
                f"[Background Task] pre-retention-cleanup: Error closing session: {e}"
            )
