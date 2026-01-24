#!/usr/bin/env python3

from typing import Dict, List, Tuple, Optional
from collections import defaultdict
from datetime import datetime
from zoneinfo import ZoneInfo
import re
import urllib.parse

from wordlists import get_wordlists
from database import get_database, DatabaseManager
from ip_utils import is_local_or_private_ip, is_valid_public_ip


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
        self.ip_counts: Dict[str, int] = defaultdict(int)
        self.path_counts: Dict[str, int] = defaultdict(int)
        self.user_agent_counts: Dict[str, int] = defaultdict(int)
        self.access_log: List[Dict] = []
        self.credential_attempts: List[Dict] = []

        # Memory limits for in-memory lists (prevents unbounded growth)
        self.max_access_log_size = 10_000  # Keep only recent 10k accesses
        self.max_credential_log_size = 5_000  # Keep only recent 5k attempts
        self.max_counter_keys = 100_000  # Max unique IPs/paths/user agents

        # Track pages visited by each IP (for good crawler limiting)
        self.ip_page_visits: Dict[str, Dict[str, object]] = defaultdict(dict)

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
        wl = get_wordlists()
        self.attack_types = wl.attack_patterns

        # Fallback if wordlists not loaded
        if not self.attack_types:
            self.attack_types = {
                "path_traversal": r"\.\.",
                "sql_injection": r"('|--|;|\bOR\b|\bUNION\b|\bSELECT\b|\bDROP\b)",
                "xss_attempt": r"(<script|javascript:|onerror=|onload=)",
                "common_probes": r"(wp-admin|phpmyadmin|\.env|\.git|/admin|/config)",
                "shell_injection": r"(\||;|`|\$\(|&&)",
            }

        # Track IPs that accessed honeypot paths from robots.txt
        self.honeypot_triggered: Dict[str, List[str]] = defaultdict(list)

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
            except Exception:
                # Database not initialized, persistence disabled
                pass
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

            # Common username field names
            username_fields = [
                "username",
                "user",
                "login",
                "email",
                "log",
                "userid",
                "account",
            ]
            for field in username_fields:
                if field in parsed and parsed[field]:
                    username = parsed[field][0]
                    break

            # Common password field names
            password_fields = ["password", "pass", "passwd", "pwd", "passphrase"]
            for field in password_fields:
                if field in parsed and parsed[field]:
                    password = parsed[field][0]
                    break

        except Exception:
            # If parsing fails, try simple regex patterns
            username_match = re.search(
                r"(?:username|user|login|email|log)=([^&\s]+)", post_data, re.IGNORECASE
            )
            password_match = re.search(
                r"(?:password|pass|passwd|pwd)=([^&\s]+)", post_data, re.IGNORECASE
            )

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

        # In-memory storage for dashboard
        self.credential_attempts.append(
            {
                "ip": ip,
                "path": path,
                "username": username,
                "password": password,
                "timestamp": datetime.now().isoformat(),
            }
        )

        # Trim if exceeding max size (prevent unbounded growth)
        if len(self.credential_attempts) > self.max_credential_log_size:
            self.credential_attempts = self.credential_attempts[
                -self.max_credential_log_size :
            ]

        # Persist to database
        if self.db:
            try:
                self.db.persist_credential(
                    ip=ip, path=path, username=username, password=password
                )
            except Exception:
                # Don't crash if database persistence fails
                pass

    def record_access(
        self,
        ip: str,
        path: str,
        user_agent: str = "",
        body: str = "",
        method: str = "GET",
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
        """
        # Skip if this is the server's own IP
        from config import get_config
        config = get_config()
        server_ip = config.get_server_ip()
        if server_ip and ip == server_ip:
            return

        self.ip_counts[ip] += 1
        self.path_counts[path] += 1
        if user_agent:
            self.user_agent_counts[user_agent] += 1

        # Path attack type detection
        attack_findings = self.detect_attack_type(path)

        # POST/PUT body attack detection
        if len(body) > 0:
            attack_findings.extend(self.detect_attack_type(body))

        is_suspicious = (
            self.is_suspicious_user_agent(user_agent)
            or self.is_honeypot_path(path)
            or len(attack_findings) > 0
        )
        is_honeypot = self.is_honeypot_path(path)

        # Track if this IP accessed a honeypot path
        if is_honeypot:
            self.honeypot_triggered[ip].append(path)

        # In-memory storage for dashboard
        self.access_log.append(
            {
                "ip": ip,
                "path": path,
                "user_agent": user_agent,
                "suspicious": is_suspicious,
                "honeypot_triggered": self.is_honeypot_path(path),
                "attack_types": attack_findings,
                "timestamp": datetime.now().isoformat(),
            }
        )

        # Trim if exceeding max size (prevent unbounded growth)
        if len(self.access_log) > self.max_access_log_size:
            self.access_log = self.access_log[-self.max_access_log_size :]

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
                )
            except Exception:
                # Don't crash if database persistence fails
                pass

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
        Increment page visit counter for an IP and return the new count.
        Implements incremental bans: each violation increases ban duration exponentially.

        Ban duration formula: base_duration * (2 ^ violation_count)
        - 1st violation: base_duration (e.g., 60 seconds)
        - 2nd violation: base_duration * 2 (120 seconds)
        - 3rd violation: base_duration * 4 (240 seconds)
        - Nth violation: base_duration * 2^(N-1)

        Args:
            client_ip: The client IP address

        Returns:
            The updated page visit count for this IP
        """
        # Skip if this is the server's own IP
        from config import get_config
        config = get_config()
        server_ip = config.get_server_ip()
        if server_ip and client_ip == server_ip:
            return 0

        try:
            # Initialize if not exists
            if client_ip not in self.ip_page_visits:
                self.ip_page_visits[client_ip] = {
                    "count": 0,
                    "ban_timestamp": None,
                    "total_violations": 0,
                    "ban_multiplier": 1,
                }

            # Increment count
            self.ip_page_visits[client_ip]["count"] += 1

            # Set ban if reached limit
            if self.ip_page_visits[client_ip]["count"] >= self.max_pages_limit:
                # Increment violation counter
                self.ip_page_visits[client_ip]["total_violations"] += 1
                violations = self.ip_page_visits[client_ip]["total_violations"]

                # Calculate exponential ban multiplier: 2^(violations - 1)
                # Violation 1: 2^0 = 1x
                # Violation 2: 2^1 = 2x
                # Violation 3: 2^2 = 4x
                # Violation 4: 2^3 = 8x, etc.
                self.ip_page_visits[client_ip]["ban_multiplier"] = 2 ** (violations - 1)

                # Set ban timestamp
                self.ip_page_visits[client_ip]["ban_timestamp"] = datetime.now().isoformat()

            return self.ip_page_visits[client_ip]["count"]

        except Exception:
            return 0

    def is_banned_ip(self, client_ip: str) -> bool:
        """
        Check if an IP is currently banned due to exceeding page visit limits.
        Uses incremental ban duration based on violation count.

        Ban duration = base_duration * (2 ^ (violations - 1))
        Each time an IP is banned again, duration doubles.

        Args:
            client_ip: The client IP address
        Returns:
            True if the IP is banned, False otherwise
        """
        try:
            if client_ip in self.ip_page_visits:
                ban_timestamp = self.ip_page_visits[client_ip].get("ban_timestamp")
                if ban_timestamp is not None:
                    # Get the ban multiplier for this violation
                    ban_multiplier = self.ip_page_visits[client_ip].get(
                        "ban_multiplier", 1
                    )

                    # Calculate effective ban duration based on violations
                    effective_ban_duration = self.ban_duration_seconds * ban_multiplier

                    # Check if ban period has expired
                    ban_time = datetime.fromisoformat(ban_timestamp)
                    time_diff = datetime.now() - ban_time

                    if time_diff.total_seconds() > effective_ban_duration:
                        # Ban expired, reset for next cycle
                        # Keep violation count for next offense
                        self.ip_page_visits[client_ip]["count"] = 0
                        self.ip_page_visits[client_ip]["ban_timestamp"] = None
                        return False
                    else:
                        # Still banned
                        return True

            return False

        except Exception:
            return False

    def get_ban_info(self, client_ip: str) -> dict:
        """
        Get detailed ban information for an IP.

        Returns:
            Dictionary with ban status, violations, and remaining ban time
        """
        try:
            if client_ip not in self.ip_page_visits:
                return {
                    "is_banned": False,
                    "violations": 0,
                    "ban_multiplier": 1,
                    "remaining_ban_seconds": 0,
                }

            ip_data = self.ip_page_visits[client_ip]
            ban_timestamp = ip_data.get("ban_timestamp")

            if ban_timestamp is None:
                return {
                    "is_banned": False,
                    "violations": ip_data.get("total_violations", 0),
                    "ban_multiplier": ip_data.get("ban_multiplier", 1),
                    "remaining_ban_seconds": 0,
                }

            # Ban is active, calculate remaining time
            ban_multiplier = ip_data.get("ban_multiplier", 1)
            effective_ban_duration = self.ban_duration_seconds * ban_multiplier

            ban_time = datetime.fromisoformat(ban_timestamp)
            time_diff = datetime.now() - ban_time
            remaining_seconds = max(
                0, effective_ban_duration - time_diff.total_seconds()
            )

            return {
                "is_banned": remaining_seconds > 0,
                "violations": ip_data.get("total_violations", 0),
                "ban_multiplier": ban_multiplier,
                "effective_ban_duration_seconds": effective_ban_duration,
                "remaining_ban_seconds": remaining_seconds,
            }

        except Exception:
            return {
                "is_banned": False,
                "violations": 0,
                "ban_multiplier": 1,
                "remaining_ban_seconds": 0,
            }
        """
        Get the current page visit count for an IP.

        Args:
            client_ip: The client IP address

        Returns:
            The page visit count for this IP
        """
        try:
            return self.ip_page_visits.get(client_ip, 0)
        except Exception:
            return 0

    def get_top_ips(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get top N IP addresses by access count (excludes local/private IPs)"""
        filtered = [
            (ip, count)
            for ip, count in self.ip_counts.items()
            if not is_local_or_private_ip(ip)
        ]
        return sorted(filtered, key=lambda x: x[1], reverse=True)[:limit]

    def get_top_paths(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get top N paths by access count"""
        return sorted(self.path_counts.items(), key=lambda x: x[1], reverse=True)[
            :limit
        ]

    def get_top_user_agents(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get top N user agents by access count"""
        return sorted(self.user_agent_counts.items(), key=lambda x: x[1], reverse=True)[
            :limit
        ]

    def get_suspicious_accesses(self, limit: int = 20) -> List[Dict]:
        """Get recent suspicious accesses (excludes local/private IPs)"""
        suspicious = [
            log
            for log in self.access_log
            if log.get("suspicious", False) and not is_local_or_private_ip(log.get("ip", ""))
        ]
        return suspicious[-limit:]

    def get_attack_type_accesses(self, limit: int = 20) -> List[Dict]:
        """Get recent accesses with detected attack types (excludes local/private IPs)"""
        attacks = [
            log
            for log in self.access_log
            if log.get("attack_types") and not is_local_or_private_ip(log.get("ip", ""))
        ]
        return attacks[-limit:]

    def get_honeypot_triggered_ips(self) -> List[Tuple[str, List[str]]]:
        """Get IPs that accessed honeypot paths (excludes local/private IPs)"""
        return [
            (ip, paths)
            for ip, paths in self.honeypot_triggered.items()
            if not is_local_or_private_ip(ip)
        ]

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

    def cleanup_memory(self) -> None:
        """
        Clean up in-memory structures to prevent unbounded growth.
        Should be called periodically (e.g., every 5 minutes).

        Trimming strategy:
        - Keep most recent N entries in logs
        - Remove oldest entries when limit exceeded
        - Clean expired ban entries from ip_page_visits
        """
        # Trim access_log to max size (keep most recent)
        if len(self.access_log) > self.max_access_log_size:
            self.access_log = self.access_log[-self.max_access_log_size:]

        # Trim credential_attempts to max size (keep most recent)
        if len(self.credential_attempts) > self.max_credential_log_size:
            self.credential_attempts = self.credential_attempts[
                -self.max_credential_log_size :
            ]

        # Clean expired ban entries from ip_page_visits
        current_time = datetime.now()
        ips_to_clean = []
        for ip, data in self.ip_page_visits.items():
            ban_timestamp = data.get("ban_timestamp")
            if ban_timestamp is not None:
                try:
                    ban_time = datetime.fromisoformat(ban_timestamp)
                    time_diff = (current_time - ban_time).total_seconds()
                    if time_diff > self.ban_duration_seconds:
                        # Ban expired, reset the entry
                        data["count"] = 0
                        data["ban_timestamp"] = None
                except (ValueError, TypeError):
                    pass

        # Optional: Remove IPs with zero activity (advanced cleanup)
        # Comment out to keep indefinite history of zero-activity IPs
        # ips_to_remove = [
        #     ip
        #     for ip, data in self.ip_page_visits.items()
        #     if data.get("count", 0) == 0 and data.get("ban_timestamp") is None
        # ]
        # for ip in ips_to_remove:
        #     del self.ip_page_visits[ip]

    def get_memory_stats(self) -> Dict[str, int]:
        """
        Get current memory usage statistics for monitoring.

        Returns:
            Dictionary with counts of in-memory items
        """
        return {
            "access_log_size": len(self.access_log),
            "credential_attempts_size": len(self.credential_attempts),
            "unique_ips_tracked": len(self.ip_counts),
            "unique_paths_tracked": len(self.path_counts),
            "unique_user_agents": len(self.user_agent_counts),
            "unique_ip_page_visits": len(self.ip_page_visits),
            "honeypot_triggered_ips": len(self.honeypot_triggered),
        }
