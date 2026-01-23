#!/usr/bin/env python3

from typing import Dict, List, Tuple, Optional
from collections import defaultdict
from datetime import datetime
from zoneinfo import ZoneInfo
import re
import urllib.parse
from wordlists import get_wordlists
from database import get_database, DatabaseManager


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
        """
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

        Args:
            ip: Client IP address
            path: Requested path
            user_agent: Client user agent string
            body: Request body (for POST/PUT)
            method: HTTP method
        """
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
        If ban timestamp exists and 60+ seconds have passed, reset the counter.

        Args:
            client_ip: The client IP address

        Returns:
            The updated page visit count for this IP
        """
        try:
            # Initialize if not exists
            if client_ip not in self.ip_page_visits:
                self.ip_page_visits[client_ip] = {"count": 0, "ban_timestamp": None}

            # Increment count
            self.ip_page_visits[client_ip]["count"] += 1

            # Set ban if reached limit
            if self.ip_page_visits[client_ip]["count"] >= self.max_pages_limit:
                self.ip_page_visits[client_ip][
                    "ban_timestamp"
                ] = datetime.now().isoformat()

            return self.ip_page_visits[client_ip]["count"]

        except Exception:
            return 0

    def is_banned_ip(self, client_ip: str) -> bool:
        """
        Check if an IP is currently banned due to exceeding page visit limits.

        Args:
            client_ip: The client IP address
        Returns:
            True if the IP is banned, False otherwise
        """
        try:
            if client_ip in self.ip_page_visits:
                ban_timestamp = self.ip_page_visits[client_ip]["ban_timestamp"]
                if ban_timestamp is not None:
                    banned = True

                # Check if ban period has expired (> 60 seconds)
                ban_time = datetime.fromisoformat(
                    self.ip_page_visits[client_ip]["ban_timestamp"]
                )
                time_diff = datetime.now() - ban_time
                if time_diff.total_seconds() > self.ban_duration_seconds:
                    self.ip_page_visits[client_ip]["count"] = 0
                    self.ip_page_visits[client_ip]["ban_timestamp"] = None
                    banned = False

            return banned

        except Exception:
            return False

    def get_page_visit_count(self, client_ip: str) -> int:
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
        """Get top N IP addresses by access count"""
        return sorted(self.ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]

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
        """Get recent suspicious accesses"""
        suspicious = [log for log in self.access_log if log.get("suspicious", False)]
        return suspicious[-limit:]

    def get_attack_type_accesses(self, limit: int = 20) -> List[Dict]:
        """Get recent accesses with detected attack types"""
        attacks = [log for log in self.access_log if log.get("attack_types")]
        return attacks[-limit:]

    def get_honeypot_triggered_ips(self) -> List[Tuple[str, List[str]]]:
        """Get IPs that accessed honeypot paths"""
        return [(ip, paths) for ip, paths in self.honeypot_triggered.items()]

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
