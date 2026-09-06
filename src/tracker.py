#!/usr/bin/env python3

import logging
import re
import urllib.parse
from datetime import datetime

from database import DatabaseManager, get_database
from ip_utils import is_ignored_ip
from tlsh_utils import tlsh_available, tlsh_hash
from wordlists import get_wordlists

logger = logging.getLogger("krawl")


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
        db_manager: DatabaseManager | None = None,
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
                "login_attempt": r"(/wp-login\.php|/wp-login|/admin/login|/admin/signin|/user/login|/users/login|/account/login|/portal/login|/secure/login|/login\.php|/login\.asp|/login\.aspx|/signin|/sign-in|/sign_in|/auth/login|/api/auth|/api/login|/api/signin|/api/token|/oauth/login|/sso/login|/xmlrpc\.php|/session/new|action=login)",
                "command_injection": r"(\||;|`|\$\(|&&)",
            }

        # Database manager for persistence (lazily initialized)
        self._db_manager = db_manager

    @property
    def db(self) -> DatabaseManager | None:
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

    def parse_credentials(self, post_data: str) -> tuple[str, str]:
        """
        Parse username and password from POST data.
        Returns tuple (username, password) or (None, None) if not found.
        """
        if not post_data:
            return None, None

        parsed = urllib.parse.parse_qs(post_data)
        wl = get_wordlists()

        def first(fields):
            for field in fields:
                if parsed.get(field):
                    return parsed[field][0]
            return None

        return first(wl.username_fields), first(wl.password_fields)

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
        increment_page_visit: bool = False,
        referer: str = "",
        file_payloads: list[dict] | None = None,
    ) -> int:
        """
        Record an access attempt.

        Stores in both in-memory structures and database.
        Skips recording if the IP is the server's own public IP.

        Args:
            ip: Client IP address
            path: Requested path
            user_agent: Client user agent string
            body: Request body (for POST/PUT)
            method: HTTP method
            raw_request: Full raw HTTP request for forensic analysis
            increment_page_visit: Also bump page visit counter in the same DB tx
            referer: Inbound HTTP Referer header (bait-chain tracking)
            file_payloads: Uploaded-file dicts to persist as captured_payloads rows

        Returns:
            The page visit count (0 when increment_page_visit is False or on error)
        """
        # Private/local/reserved IPs (e.g. k8s health-check sources) are never
        # tracked, categorized, or banned.
        if is_ignored_ip(ip):
            return 0

        # Skip if this is the server's own IP
        from config import get_config

        config = get_config()
        server_ip = config.get_server_ip()
        if server_ip and ip == server_ip:
            return 0

        # login_attempt only makes sense for POST requests
        path_exclude = {"login_attempt"} if method != "POST" else None
        attack_findings = self.detect_attack_type(path, exclude=path_exclude)

        # Bait-chain referer + file payloads are derived from the raw request so
        # every recording path (honeypot dependency, catch-all POST, deception
        # middleware) captures them even when the caller didn't thread them through.
        if not referer and raw_request and config.referer_enabled:
            _m = re.search(r"\r\nReferer:\s*([^\r\n]+)", raw_request, re.IGNORECASE)
            if _m:
                referer = _m.group(1).strip()
        if file_payloads is None and raw_request and config.tlsh_enabled:
            from tlsh_utils import extract_file_payloads

            file_payloads = extract_file_payloads(raw_request)

        # common_probes and login_attempt are path-based — skip them on body to avoid
        # false positives from form fields like redirect_to=/wp-admin/
        if len(body) > 0:
            decoded_body = urllib.parse.unquote(body)
            attack_findings.extend(
                self.detect_attack_type(
                    decoded_body, exclude={"common_probes", "login_attempt"}
                )
            )
            # If credentials were submitted (even on non-login paths like AI-generated pages),
            # tag as login_attempt
            if method == "POST" and not any(
                t == "login_attempt" for t, _ in attack_findings
            ):
                username, password = self.parse_credentials(decoded_body)
                if username or password:
                    attack_findings.append(("login_attempt", "/login"))

        attack_types = [t for t, _ in attack_findings]
        matched_patterns = {t: m for t, m in attack_findings}

        # TLSH fuzzy hash of the payload (decoded body, or path for path-only hits)
        # for near-duplicate variant clustering across attackers.
        tlsh_hashes: dict[str, str] = {}
        if attack_findings and config.tlsh_enabled and tlsh_available():
            _payload = (urllib.parse.unquote(body) if body else path).encode(
                "utf-8", errors="replace"
            )
            _digest = tlsh_hash(_payload)
            if _digest:
                for t in attack_types:
                    tlsh_hashes[t] = _digest

        # Incremental campaign clustering: assign each distinct digest to a
        # cluster (or seed a new one) before persisting, so every row carries
        # its cluster_id and the Recurring Patterns panel needs no per-query O(n²).
        tlsh_clusters: dict[str, str] = {}
        if tlsh_hashes and self.db:
            _seen_ts = datetime.now()
            _by_digest: dict[str, str] = {}
            for t, digest in tlsh_hashes.items():
                cid = _by_digest.get(digest) or self.db.payloads.assign_cluster(
                    digest, _seen_ts, threshold=config.tlsh_cluster_threshold
                )
                if cid:
                    _by_digest[digest] = cid
                    tlsh_clusters[t] = cid
        if file_payloads and self.db:
            _seen_ts = datetime.now()
            for fp in file_payloads:
                if fp.get("tlsh_hash") and not fp.get("cluster_id"):
                    fp["cluster_id"] = self.db.payloads.assign_cluster(
                        fp["tlsh_hash"],
                        _seen_ts,
                        threshold=config.tlsh_cluster_threshold,
                    )

        is_suspicious = (
            self.is_suspicious_user_agent(user_agent)
            or self.is_honeypot_path(path)
            or len(attack_types) > 0
        )
        is_honeypot = self.is_honeypot_path(path)

        # Persist to database
        if self.db:
            try:
                return self.db.persist_access(
                    ip=ip,
                    path=path,
                    user_agent=user_agent,
                    method=method,
                    is_suspicious=is_suspicious,
                    is_honeypot_trigger=is_honeypot,
                    attack_types=attack_types if attack_types else None,
                    matched_patterns=matched_patterns if matched_patterns else None,
                    tlsh_hashes=tlsh_hashes if tlsh_hashes else None,
                    tlsh_clusters=tlsh_clusters if tlsh_clusters else None,
                    raw_request=raw_request if raw_request else None,
                    referer=referer if referer else None,
                    file_payloads=file_payloads,
                    increment_page_visit=increment_page_visit,
                    max_pages_limit=self.max_pages_limit if increment_page_visit else 0,
                )
            except Exception as e:
                logger.error(f"Failed to persist access record: {e}")
        return 0

    def detect_attack_type(
        self, data: str, exclude: set[str] | None = None
    ) -> list[tuple[str, str]]:
        """
        Returns a list of (attack_type, matched_substring) tuples found in data.
        """
        findings = []
        for name, pattern in self.attack_types.items():
            if exclude and name in exclude:
                continue
            m = re.search(pattern, data, re.IGNORECASE)
            if m:
                findings.append((name, m.group(0)[:256]))
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

            ip_stats = db.ip_stats.get_ip_stats_by_ip(safe_ip)
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
        # Private/local/reserved IPs are never tracked or banned.
        if is_ignored_ip(client_ip):
            return 0

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

        return self.db.ip_stats.is_banned_ip(client_ip, self.ban_duration_seconds)

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

        return self.db.ip_stats.get_ban_info(client_ip, self.ban_duration_seconds)

    def get_stats(self) -> dict:
        """Get statistics summary from database."""
        if not self.db:
            raise RuntimeError("Database not available for dashboard stats")

        # Get aggregate counts from database
        stats = self.db.access_logs.get_dashboard_counts()

        # Add detailed lists from database
        stats["top_ips"] = self.db.analytics.get_top_ips(10)
        stats["top_paths"] = self.db.analytics.get_top_paths(10)
        stats["top_user_agents"] = self.db.analytics.get_top_user_agents(10)
        stats["recent_suspicious"] = self.db.access_logs.get_recent_suspicious(20)
        stats["honeypot_triggered_ips"] = (
            self.db.access_logs.get_honeypot_triggered_ips()
        )
        stats["attack_types"] = self.db.access_logs.get_recent_attacks(20)
        stats["credential_attempts"] = self.db.credentials.get_list(limit=50)

        return stats
