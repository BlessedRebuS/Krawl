#!/usr/bin/env python3

import logging
import re
import urllib.parse
from datetime import datetime

from database import DatabaseManager, get_database
from detection import DetectionCoordinator, DetectionFinding, get_detection
from ip_utils import is_ignored_ip

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
        detector: DetectionCoordinator | None = None,
    ):
        """
        Initialize the access tracker.

        Args:
            db_manager: Optional DatabaseManager for persistence.
                        If None, will use the global singleton.
        """
        self.max_pages_limit = max_pages_limit
        self.ban_duration_seconds = ban_duration_seconds

        # None follows the live detector, which is replaced when an analyst
        # uploads or deletes a rule file; tests inject a fixed one.
        self._detector = detector

        # Database manager for persistence (lazily initialized)
        self._db_manager = db_manager

    @property
    def detector(self) -> DetectionCoordinator:
        return self._detector or get_detection()

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
        from config import get_config

        config = get_config()

        def first(fields):
            for field in fields:
                if parsed.get(field):
                    return parsed[field][0]
            return None

        return first(config.credential_username_fields), first(
            config.credential_password_fields
        )

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
        query: str = "",
        method: str = "GET",
        raw_request: str = "",
        increment_page_visit: bool = False,
        referer: str = "",
        file_payloads: list[dict] | None = None,
        target_host: str | None = None,
        detection_findings: list[DetectionFinding] | None = None,
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
            query: Raw URL query string
            method: HTTP method
            raw_request: Full raw HTTP request for forensic analysis
            increment_page_visit: Also bump page visit counter in the same DB tx
            referer: Inbound HTTP Referer header (bait-chain tracking)
            file_payloads: Uploaded-file dicts to persist as captured_payloads rows
            target_host: Host header captured directly from the live request

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

        # Derive bait-chain and upload evidence from the raw request for callers
        # that did not pass the structured values explicitly.
        if not referer and raw_request and config.referer_enabled:
            match = re.search(r"\r\nReferer:\s*([^\r\n]+)", raw_request, re.IGNORECASE)
            if match:
                referer = match.group(1).strip()
        if file_payloads is None and raw_request:
            from tlsh_utils import extract_file_payloads

            file_payloads = extract_file_payloads(
                raw_request, compute_tlsh=config.tlsh_enabled
            )

        findings = detection_findings
        if findings is None:
            findings = self.detector.scan_request(
                path=path,
                query=query,
                body=body,
                user_agent=user_agent,
                method=method,
            )

        # Credentials submitted on a non-login path remain a login attempt.
        if method == "POST" and not any(
            item.attack_type == "login_attempt" for item in findings
        ):
            username, password = self.parse_credentials(urllib.parse.unquote(body))
            if username or password:
                findings = [
                    *findings,
                    DetectionFinding(
                        attack_type="login_attempt",
                        matched_pattern="/login",
                        source="credential_fields",
                        scan_target="body",
                        severity=4,
                        rule_name="credential_fields",
                    ),
                ]

        attack_findings = [item for item in findings if item.classification == "attack"]
        attack_types = [item.attack_type for item in attack_findings]
        matched_patterns = {
            item.attack_type: item.matched_pattern for item in attack_findings
        }
        rule_names = {
            item.attack_type: item.rule_name
            for item in attack_findings
            if item.rule_name
        }

        from request_metadata import extract_request_metadata, normalize_target_host

        derived_host, request_assets = extract_request_metadata(raw_request)
        target_host = normalize_target_host(target_host or "") or derived_host

        # TLSH hashing + campaign clustering of attack bodies moved to the
        # scheduled hash-payloads task (reads the persisted raw_request), so
        # ingest stays cheap. Captured files stay inline: uploads are rare and
        # already fully parsed.
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
            not user_agent
            or any(item.classification == "suspicious" for item in findings)
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
                    rule_names=rule_names or None,
                    raw_request=raw_request if raw_request else None,
                    referer=referer if referer else None,
                    file_payloads=file_payloads,
                    target_host=target_host,
                    request_assets=request_assets,
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
        findings = self.detector.scan_value(data, target="path", exclude=exclude)
        return [
            (item.attack_type, item.matched_pattern)
            for item in findings
            if item.classification == "attack"
        ]

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
        return any(
            item.classification == "suspicious"
            for item in self.detector.scan_value(user_agent, target="user_agent")
        )

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
