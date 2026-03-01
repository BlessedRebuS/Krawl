#!/usr/bin/env python3

from typing import Dict, Tuple, Optional
import logging
import re
import urllib.parse

from wordlists import get_wordlists
from database import get_database, DatabaseManager

logger = logging.getLogger("krawl")

# Module-level singleton for background task access
_tracker_instance: "AccessTracker | None" = None


def get_tracker() -> "AccessTracker | None":
    """Get the global AccessTracker singleton (set during app startup)."""
    return _tracker_instance


def set_tracker(tracker: "AccessTracker"):
    """Store the AccessTracker singleton for background task access."""
    global _tracker_instance
    _tracker_instance = tracker


class AccessTracker:
    """
    Track IP addresses and paths accessed.

    Maintains in-memory structures for fast dashboard access and
    persists data to SQLite for long-term storage and analysis.
    """

    def __init__(
        self,
        max_pages_limit,
        ban_duration_seconds,
        db_manager: Optional[DatabaseManager] = None,
    ):
        """
        Initialize the access tracker.

        Args:
            db_manager: Optional DatabaseManager for persistence.
                        If None, will use the global singleton.
        """
        self.max_pages_limit = max_pages_limit
        self.ban_duration_seconds = ban_duration_seconds

        # Load suspicious patterns from wordlists
        wl = get_wordlists()
        self.suspicious_patterns = wl.suspicious_patterns

        # Fallback if wordlists not loaded
        if not self.suspicious_patterns:
            self.suspicious_patterns = [
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

        # Load attack patterns from wordlists
        self.attack_types = wl.attack_patterns

        # Fallback if wordlists not loaded
        if not self.attack_types:
            self.attack_types = {
                "path_traversal": r"\.\.",
                "sql_injection": r"('|--|;|\bOR\b|\bUNION\b|\bSELECT\b|\bDROP\b)",
                "xss_attempt": r"(<script|javascript:|onerror=|onload=)",
                "common_probes": r"(/admin|/backup|/config|/database|/private|/uploads|/wp-admin|/login|/phpMyAdmin|/phpmyadmin|/users|/search|/contact|/info|/input|/feedback|/server|/api/v1/|/api/v2/|/api/search|/api/sql|/api/database|\.env|/credentials\.txt|/passwords\.txt|\.git|/backup\.sql|/db_backup\.sql)",
                "command_injection": r"(\||;|`|\$\(|&&)",
            }

        # Database manager for persistence (lazily initialized)
        self._db_manager = db_manager

    @property
    def db(self) -> Optional[DatabaseManager]:
        """
        Get the database manager, lazily initializing if needed.

        Returns:
            DatabaseManager instance or None if not available
        """
        if self._db_manager is None:
            try:
                self._db_manager = get_database()
            except Exception as e:
                logger.error(f"Failed to initialize database manager: {e}")
        return self._db_manager

    def parse_credentials(self, post_data: str) -> Tuple[str, str]:
        """
        Parse username and password from POST data.
        Returns tuple (username, password) or (None, None) if not found.
        """
        if not post_data:
            return None, None

        username = None
        password = None

        try:
            # Parse URL-encoded form data
            parsed = urllib.parse.parse_qs(post_data)

            # Get credential field names from wordlists
            wl = get_wordlists()
            username_fields = wl.username_fields
            password_fields = wl.password_fields

            # Fallback if wordlists not loaded
            if not username_fields:
                username_fields = [
                    "username",
                    "user",
                    "login",
                    "email",
                    "log",
                    "userid",
                    "account",
                ]
            if not password_fields:
                password_fields = ["password", "pass", "passwd", "pwd", "passphrase"]

            for field in username_fields:
                if field in parsed and parsed[field]:
                    username = parsed[field][0]
                    break

            for field in password_fields:
                if field in parsed and parsed[field]:
                    password = parsed[field][0]
                    break

        except Exception:
            # If parsing fails, try simple regex patterns
            wl = get_wordlists()
            username_fields = wl.username_fields or [
                "username",
                "user",
                "login",
                "email",
                "log",
            ]
            password_fields = wl.password_fields or [
                "password",
                "pass",
                "passwd",
                "pwd",
            ]

            # Build regex pattern from wordlist fields
            username_pattern = "(?:" + "|".join(username_fields) + ")=([^&\\s]+)"
            password_pattern = "(?:" + "|".join(password_fields) + ")=([^&\\s]+)"

            username_match = re.search(username_pattern, post_data, re.IGNORECASE)
            password_match = re.search(password_pattern, post_data, re.IGNORECASE)

            if username_match:
                username = urllib.parse.unquote_plus(username_match.group(1))
            if password_match:
                password = urllib.parse.unquote_plus(password_match.group(1))

        return username, password

    def record_credential_attempt(
        self, ip: str, path: str, username: str, password: str
    ):
        """
        Record a credential login attempt.

        Stores in both in-memory list and SQLite database.
        Skips recording if the IP is the server's own public IP.
        """
        # Skip if this is the server's own IP
        from config import get_config

        config = get_config()
        server_ip = config.get_server_ip()
        if server_ip and ip == server_ip:
            return

        # Persist to database
        if self.db:
            try:
                self.db.persist_credential(
                    ip=ip, path=path, username=username, password=password
                )
            except Exception as e:
                logger.error(f"Failed to persist credential attempt: {e}")

    def record_access(
        self,
        ip: str,
        path: str,
        user_agent: str = "",
        body: str = "",
        method: str = "GET",
        raw_request: str = "",
    ):
        """
        Record an access attempt.

        Stores in both in-memory structures and SQLite database.
        Skips recording if the IP is the server's own public IP.

        Args:
            ip: Client IP address
            path: Requested path
            user_agent: Client user agent string
            body: Request body (for POST/PUT)
            method: HTTP method
            raw_request: Full raw HTTP request for forensic analysis
        """
        # Skip if this is the server's own IP
        from config import get_config

        config = get_config()
        server_ip = config.get_server_ip()
        if server_ip and ip == server_ip:
            return

        # Path attack type detection
        attack_findings = self.detect_attack_type(path)

        # POST/PUT body attack detection
        if len(body) > 0:
            # Decode URL-encoded body so patterns can match (e.g., %3Cscript%3E -> <script>)
            decoded_body = urllib.parse.unquote(body)
            attack_findings.extend(self.detect_attack_type(decoded_body))

        is_suspicious = (
            self.is_suspicious_user_agent(user_agent)
            or self.is_honeypot_path(path)
            or len(attack_findings) > 0
        )
        is_honeypot = self.is_honeypot_path(path)

        # In-memory storage for dashboard
        # Persist to database
        if self.db:
            try:
                self.db.persist_access(
                    ip=ip,
                    path=path,
                    user_agent=user_agent,
                    method=method,
                    is_suspicious=is_suspicious,
                    is_honeypot_trigger=is_honeypot,
                    attack_types=attack_findings if attack_findings else None,
                    raw_request=raw_request if raw_request else None,
                )
            except Exception as e:
                logger.error(f"Failed to persist access record: {e}")

    def detect_attack_type(self, data: str) -> list[str]:
        """
        Returns a list of all attack types found in path data
        """
        findings = []
        for name, pattern in self.attack_types.items():
            if re.search(pattern, data, re.IGNORECASE):
                findings.append(name)
        return findings

    def is_honeypot_path(self, path: str) -> bool:
        """Check if path is one of the honeypot traps from robots.txt"""
        honeypot_paths = [
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
        ]
        return path in honeypot_paths or any(
            hp in path.lower()
            for hp in [
                "/backup",
                "/admin",
                "/config",
                "/private",
                "/database",
                "phpmyadmin",
            ]
        )

    def is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Check if user agent matches suspicious patterns"""
        if not user_agent:
            return True
        ua_lower = user_agent.lower()
        return any(pattern in ua_lower for pattern in self.suspicious_patterns)

    def get_category_by_ip(self, client_ip: str) -> str:
        """
        Check if an IP has been categorized as a 'good crawler' in the database.
        Uses the IP category from IpStats table.

        Args:
            client_ip: The client IP address (will be sanitized)

        Returns:
            True if the IP is categorized as 'good crawler', False otherwise
        """
        try:
            from sanitizer import sanitize_ip

            # Sanitize the IP address
            safe_ip = sanitize_ip(client_ip)

            # Query the database for this IP's category
            db = self.db
            if not db:
                return False

            ip_stats = db.get_ip_stats_by_ip(safe_ip)
            if not ip_stats or not ip_stats.get("category"):
                return False

            # Check if category matches "good crawler"
            category = ip_stats.get("category", "").lower().strip()
            return category

        except Exception as e:
            # Log but don't crash on database errors
            import logging

            logging.error(f"Error checking IP category for {client_ip}: {str(e)}")
            return False

    def increment_page_visit(self, client_ip: str) -> int:
        """
        Increment page visit counter for an IP via DB and return the new count.

        Args:
            client_ip: The client IP address

        Returns:
            The updated page visit count for this IP
        """
        from config import get_config

        config = get_config()
        server_ip = config.get_server_ip()
        if server_ip and client_ip == server_ip:
            return 0

        if not self.db:
            return 0

        return self.db.increment_page_visit(client_ip, self.max_pages_limit)

    def is_banned_ip(self, client_ip: str) -> bool:
        """
        Check if an IP is currently banned.

        Args:
            client_ip: The client IP address
        Returns:
            True if the IP is banned, False otherwise
        """
        if not self.db:
            return False

        return self.db.is_banned_ip(client_ip, self.ban_duration_seconds)

    def get_ban_info(self, client_ip: str) -> dict:
        """
        Get detailed ban information for an IP.

        Returns:
            Dictionary with ban status, violations, and remaining ban time
        """
        if not self.db:
            return {
                "is_banned": False,
                "violations": 0,
                "ban_multiplier": 1,
                "remaining_ban_seconds": 0,
            }

        return self.db.get_ban_info(client_ip, self.ban_duration_seconds)

    def get_stats(self) -> Dict:
        """Get statistics summary from database."""
        if not self.db:
            raise RuntimeError("Database not available for dashboard stats")

        # Get aggregate counts from database
        stats = self.db.get_dashboard_counts()

        # Add detailed lists from database
        stats["top_ips"] = self.db.get_top_ips(10)
        stats["top_paths"] = self.db.get_top_paths(10)
        stats["top_user_agents"] = self.db.get_top_user_agents(10)
        stats["recent_suspicious"] = self.db.get_recent_suspicious(20)
        stats["honeypot_triggered_ips"] = self.db.get_honeypot_triggered_ips()
        stats["attack_types"] = self.db.get_recent_attacks(20)
        stats["credential_attempts"] = self.db.get_credential_attempts(limit=50)

        return stats
