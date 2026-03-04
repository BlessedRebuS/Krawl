#!/usr/bin/env python3

"""
Database singleton module for the Krawl honeypot.
Provides SQLAlchemy session management and database initialization.
"""

import os
import stat
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from zoneinfo import ZoneInfo

from sqlalchemy import create_engine, func, distinct, case, event, or_
from sqlalchemy.orm import sessionmaker, scoped_session, Session
from sqlalchemy.engine import Engine

from ip_utils import is_local_or_private_ip, is_valid_public_ip


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable WAL mode and set busy timeout for SQLite connections."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=30000")
    cursor.close()


from models import (
    Base,
    AccessLog,
    CredentialAttempt,
    AttackDetection,
    IpStats,
    CategoryHistory,
)
from sanitizer import (
    sanitize_ip,
    sanitize_path,
    sanitize_user_agent,
    sanitize_credential,
    sanitize_attack_pattern,
)

from logger import get_app_logger

applogger = get_app_logger()


class DatabaseManager:
    """
    Singleton database manager for the Krawl honeypot.

    Handles database initialization, session management, and provides
    methods for persisting access logs, credentials, and attack detections.
    """

    _instance: Optional["DatabaseManager"] = None

    def __new__(cls) -> "DatabaseManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def initialize(self, database_path: str = "data/krawl.db") -> None:
        """
        Initialize the database connection and create tables.

        Args:
            database_path: Path to the SQLite database file
        """
        if self._initialized:
            return

        # Create data directory if it doesn't exist
        data_dir = os.path.dirname(database_path)
        if data_dir and not os.path.exists(data_dir):
            os.makedirs(data_dir, exist_ok=True)

        # Create SQLite database with check_same_thread=False for multi-threaded access
        database_url = f"sqlite:///{database_path}"
        self._engine = create_engine(
            database_url,
            connect_args={"check_same_thread": False},
            echo=False,  # Set to True for SQL debugging
        )

        # Create session factory with scoped_session for thread safety
        session_factory = sessionmaker(bind=self._engine)
        self._Session = scoped_session(session_factory)

        # Create all tables
        Base.metadata.create_all(self._engine)

        # Run automatic migrations for backward compatibility
        self._run_migrations(database_path)

        # Run schema migrations (columns & indexes on existing tables)
        from migrations.runner import run_migrations

        run_migrations(database_path)

        # Set restrictive file permissions (owner read/write only)
        if os.path.exists(database_path):
            try:
                os.chmod(database_path, stat.S_IRUSR | stat.S_IWUSR)  # 600
            except OSError:
                # May fail on some systems, not critical
                pass

        self._initialized = True

    def _run_migrations(self, database_path: str) -> None:
        """
        Run automatic migrations for backward compatibility.
        Adds missing columns that were added in newer versions.

        Args:
            database_path: Path to the SQLite database file
        """
        import sqlite3

        try:
            conn = sqlite3.connect(database_path)
            cursor = conn.cursor()

            # Check if latitude/longitude columns exist
            cursor.execute("PRAGMA table_info(ip_stats)")
            columns = [row[1] for row in cursor.fetchall()]

            migrations_run = []

            # Add latitude column if missing
            if "latitude" not in columns:
                cursor.execute("ALTER TABLE ip_stats ADD COLUMN latitude REAL")
                migrations_run.append("latitude")

            # Add longitude column if missing
            if "longitude" not in columns:
                cursor.execute("ALTER TABLE ip_stats ADD COLUMN longitude REAL")
                migrations_run.append("longitude")

            # Add new geolocation columns
            if "country" not in columns:
                cursor.execute("ALTER TABLE ip_stats ADD COLUMN country VARCHAR(100)")
                migrations_run.append("country")

            if "region" not in columns:
                cursor.execute("ALTER TABLE ip_stats ADD COLUMN region VARCHAR(2)")
                migrations_run.append("region")

            if "region_name" not in columns:
                cursor.execute(
                    "ALTER TABLE ip_stats ADD COLUMN region_name VARCHAR(100)"
                )
                migrations_run.append("region_name")

            if "timezone" not in columns:
                cursor.execute("ALTER TABLE ip_stats ADD COLUMN timezone VARCHAR(50)")
                migrations_run.append("timezone")

            if "isp" not in columns:
                cursor.execute("ALTER TABLE ip_stats ADD COLUMN isp VARCHAR(100)")
                migrations_run.append("isp")

            if "is_proxy" not in columns:
                cursor.execute("ALTER TABLE ip_stats ADD COLUMN is_proxy BOOLEAN")
                migrations_run.append("is_proxy")

            if "is_hosting" not in columns:
                cursor.execute("ALTER TABLE ip_stats ADD COLUMN is_hosting BOOLEAN")
                migrations_run.append("is_hosting")

            if "reverse" not in columns:
                cursor.execute("ALTER TABLE ip_stats ADD COLUMN reverse VARCHAR(255)")
                migrations_run.append("reverse")

            if migrations_run:
                conn.commit()
                applogger.info(
                    f"Auto-migration: Added columns {', '.join(migrations_run)} to ip_stats table"
                )

            conn.close()
        except Exception as e:
            applogger.error(f"Auto-migration failed: {e}")
            # Don't raise - allow app to continue even if migration fails

    @property
    def session(self) -> Session:
        """Get a thread-local database session."""
        if not self._initialized:
            raise RuntimeError(
                "DatabaseManager not initialized. Call initialize() first."
            )
        return self._Session()

    def close_session(self) -> None:
        """Close the current thread-local session."""
        if self._initialized:
            self._Session.remove()

    def persist_access(
        self,
        ip: str,
        path: str,
        user_agent: str = "",
        method: str = "GET",
        is_suspicious: bool = False,
        is_honeypot_trigger: bool = False,
        attack_types: Optional[List[str]] = None,
        matched_patterns: Optional[Dict[str, str]] = None,
        raw_request: Optional[str] = None,
    ) -> Optional[int]:
        """
        Persist an access log entry to the database.

        Args:
            ip: Client IP address
            path: Requested path
            user_agent: Client user agent string
            method: HTTP method (GET, POST, HEAD)
            is_suspicious: Whether the request was flagged as suspicious
            is_honeypot_trigger: Whether a honeypot path was accessed
            attack_types: List of detected attack types
            matched_patterns: Dict mapping attack_type to matched pattern
            raw_request: Full raw HTTP request for forensic analysis

        Returns:
            The ID of the created AccessLog record, or None on error
        """
        session = self.session
        try:
            # Create access log with sanitized fields
            access_log = AccessLog(
                ip=sanitize_ip(ip),
                path=sanitize_path(path),
                user_agent=sanitize_user_agent(user_agent),
                method=method[:10],
                is_suspicious=is_suspicious,
                is_honeypot_trigger=is_honeypot_trigger,
                timestamp=datetime.now(),
                raw_request=raw_request,
            )
            session.add(access_log)
            session.flush()  # Get the ID before committing

            # Add attack detections if any
            if attack_types:
                matched_patterns = matched_patterns or {}
                for attack_type in attack_types:
                    detection = AttackDetection(
                        access_log_id=access_log.id,
                        attack_type=attack_type[:50],
                        matched_pattern=sanitize_attack_pattern(
                            matched_patterns.get(attack_type, "")
                        ),
                    )
                    session.add(detection)

            # Update IP stats
            self._update_ip_stats(session, ip, is_suspicious)

            session.commit()
            return access_log.id

        except Exception as e:
            session.rollback()
            # Log error but don't crash - database persistence is secondary to honeypot function
            applogger.critical(f"Database error persisting access: {e}")
            return None
        finally:
            self.close_session()

    def persist_credential(
        self,
        ip: str,
        path: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> Optional[int]:
        """
        Persist a credential attempt to the database.

        Args:
            ip: Client IP address
            path: Login form path
            username: Submitted username
            password: Submitted password

        Returns:
            The ID of the created CredentialAttempt record, or None on error
        """
        session = self.session
        try:
            credential = CredentialAttempt(
                ip=sanitize_ip(ip),
                path=sanitize_path(path),
                username=sanitize_credential(username),
                password=sanitize_credential(password),
                timestamp=datetime.now(),
            )
            session.add(credential)
            session.commit()
            return credential.id

        except Exception as e:
            session.rollback()
            applogger.critical(f"Database error persisting credential: {e}")
            return None
        finally:
            self.close_session()

    def _update_ip_stats(
        self, session: Session, ip: str, is_suspicious: bool = False
    ) -> None:
        """
        Update IP statistics (upsert pattern).

        Args:
            session: Active database session
            ip: IP address to update
            is_suspicious: Whether the request was flagged as suspicious
        """
        sanitized_ip = sanitize_ip(ip)
        now = datetime.now()

        ip_stats = session.query(IpStats).filter(IpStats.ip == sanitized_ip).first()

        if ip_stats:
            ip_stats.total_requests += 1
            ip_stats.last_seen = now
            if is_suspicious:
                ip_stats.need_reevaluation = True
        else:
            ip_stats = IpStats(
                ip=sanitized_ip,
                total_requests=1,
                first_seen=now,
                last_seen=now,
                need_reevaluation=is_suspicious,
            )
            session.add(ip_stats)

    def increment_page_visit(self, ip: str, max_pages_limit: int) -> int:
        """
        Increment the page visit counter for an IP and apply ban if limit reached.

        Args:
            ip: Client IP address
            max_pages_limit: Page visit threshold before banning

        Returns:
            The updated page visit count
        """
        session = self.session
        try:
            sanitized_ip = sanitize_ip(ip)
            ip_stats = session.query(IpStats).filter(IpStats.ip == sanitized_ip).first()

            if not ip_stats:
                now = datetime.now()
                ip_stats = IpStats(
                    ip=sanitized_ip,
                    total_requests=0,
                    first_seen=now,
                    last_seen=now,
                    page_visit_count=1,
                )
                session.add(ip_stats)
                session.commit()
                return 1

            ip_stats.page_visit_count = (ip_stats.page_visit_count or 0) + 1

            if ip_stats.page_visit_count >= max_pages_limit:
                ip_stats.total_violations = (ip_stats.total_violations or 0) + 1
                ip_stats.ban_multiplier = 2 ** (ip_stats.total_violations - 1)
                ip_stats.ban_timestamp = datetime.now()

            session.commit()
            return ip_stats.page_visit_count

        except Exception as e:
            session.rollback()
            applogger.error(f"Error incrementing page visit for {ip}: {e}")
            return 0
        finally:
            self.close_session()

    def is_banned_ip(self, ip: str, ban_duration_seconds: int) -> bool:
        """
        Check if an IP is currently banned.

        Args:
            ip: Client IP address
            ban_duration_seconds: Base ban duration in seconds

        Returns:
            True if the IP is currently banned
        """
        session = self.session
        try:
            sanitized_ip = sanitize_ip(ip)
            ip_stats = session.query(IpStats).filter(IpStats.ip == sanitized_ip).first()

            if not ip_stats or ip_stats.ban_timestamp is None:
                return False

            effective_duration = ban_duration_seconds * (ip_stats.ban_multiplier or 1)
            elapsed = (datetime.now() - ip_stats.ban_timestamp).total_seconds()

            if elapsed > effective_duration:
                # Ban expired — reset count for next cycle
                ip_stats.page_visit_count = 0
                ip_stats.ban_timestamp = None
                session.commit()
                return False

            return True

        except Exception as e:
            applogger.error(f"Error checking ban status for {ip}: {e}")
            return False
        finally:
            self.close_session()

    def get_ban_info(self, ip: str, ban_duration_seconds: int) -> dict:
        """
        Get detailed ban information for an IP.

        Args:
            ip: Client IP address
            ban_duration_seconds: Base ban duration in seconds

        Returns:
            Dictionary with ban status details
        """
        session = self.session
        try:
            sanitized_ip = sanitize_ip(ip)
            ip_stats = session.query(IpStats).filter(IpStats.ip == sanitized_ip).first()

            if not ip_stats:
                return {
                    "is_banned": False,
                    "violations": 0,
                    "ban_multiplier": 1,
                    "remaining_ban_seconds": 0,
                }

            violations = ip_stats.total_violations or 0
            multiplier = ip_stats.ban_multiplier or 1

            if ip_stats.ban_timestamp is None:
                return {
                    "is_banned": False,
                    "violations": violations,
                    "ban_multiplier": multiplier,
                    "remaining_ban_seconds": 0,
                }

            effective_duration = ban_duration_seconds * multiplier
            elapsed = (datetime.now() - ip_stats.ban_timestamp).total_seconds()
            remaining = max(0, effective_duration - elapsed)

            return {
                "is_banned": remaining > 0,
                "violations": violations,
                "ban_multiplier": multiplier,
                "effective_ban_duration_seconds": effective_duration,
                "remaining_ban_seconds": remaining,
            }

        except Exception as e:
            applogger.error(f"Error getting ban info for {ip}: {e}")
            return {
                "is_banned": False,
                "violations": 0,
                "ban_multiplier": 1,
                "remaining_ban_seconds": 0,
            }
        finally:
            self.close_session()

    def update_ip_stats_analysis(
        self,
        ip: str,
        analyzed_metrics: Dict[str, object],
        category: str,
        category_scores: Dict[str, int],
        last_analysis: datetime,
    ) -> None:
        """
        Update IP statistics (ip is already persisted).
        Records category change in history if category has changed.

        Args:
            ip: IP address to update
            analyzed_metrics: metric values analyzed be the analyzer
            category: inferred category
            category_scores: inferred category scores
            last_analysis: timestamp of last analysis

        """
        applogger.debug(
            f"Analyzed metrics {analyzed_metrics}, category {category}, category scores {category_scores}, last analysis {last_analysis}"
        )
        applogger.info(f"IP: {ip} category has been updated to {category}")

        session = self.session
        sanitized_ip = sanitize_ip(ip)
        ip_stats = session.query(IpStats).filter(IpStats.ip == sanitized_ip).first()

        if not ip_stats:
            applogger.warning(
                f"No IpStats record found for {sanitized_ip}, creating one."
            )
            now = datetime.now()
            ip_stats = IpStats(
                ip=sanitized_ip, total_requests=0, first_seen=now, last_seen=now
            )
            session.add(ip_stats)

        # Check if category has changed and record it
        old_category = ip_stats.category
        if old_category != category:
            self._record_category_change(
                sanitized_ip, old_category, category, last_analysis
            )

        ip_stats.analyzed_metrics = analyzed_metrics
        ip_stats.category = category
        ip_stats.category_scores = category_scores
        ip_stats.last_analysis = last_analysis
        ip_stats.need_reevaluation = False

        try:
            session.commit()
        except Exception as e:
            session.rollback()
            applogger.error(f"Error updating IP stats analysis: {e}")

    def manual_update_category(self, ip: str, category: str) -> None:
        """
        Update IP category as a result of a manual intervention by an admin

        Args:
            ip: IP address to update
            category: selected category

        """
        session = self.session
        sanitized_ip = sanitize_ip(ip)
        ip_stats = session.query(IpStats).filter(IpStats.ip == sanitized_ip).first()

        if not ip_stats:
            applogger.warning(f"No IpStats record found for {sanitized_ip}")
            return

        # Record the manual category change
        old_category = ip_stats.category
        if old_category != category:
            self._record_category_change(
                sanitized_ip, old_category, category, datetime.now()
            )

        ip_stats.category = category
        ip_stats.manual_category = True

        try:
            session.commit()
        except Exception as e:
            session.rollback()
            applogger.error(f"Error updating manual category: {e}")

    def _record_category_change(
        self,
        ip: str,
        old_category: Optional[str],
        new_category: str,
        timestamp: datetime,
    ) -> None:
        """
        Internal method to record category changes in history.
        Records all category changes including initial categorization.

        Args:
            ip: IP address
            old_category: Previous category (None if first categorization)
            new_category: New category
            timestamp: When the change occurred
        """
        session = self.session
        try:
            history_entry = CategoryHistory(
                ip=ip,
                old_category=old_category,
                new_category=new_category,
                timestamp=timestamp,
            )
            session.add(history_entry)
            session.commit()
        except Exception as e:
            session.rollback()
            applogger.error(f"Error recording category change: {e}")

    def get_category_history(self, ip: str) -> List[Dict[str, Any]]:
        """
        Retrieve category change history for a specific IP.

        Args:
            ip: IP address to get history for

        Returns:
            List of category change records ordered by timestamp
        """
        session = self.session
        try:
            sanitized_ip = sanitize_ip(ip)
            history = (
                session.query(CategoryHistory)
                .filter(CategoryHistory.ip == sanitized_ip)
                .order_by(CategoryHistory.timestamp.asc())
                .all()
            )

            return [
                {
                    "old_category": h.old_category,
                    "new_category": h.new_category,
                    "timestamp": h.timestamp.isoformat(),
                }
                for h in history
            ]
        finally:
            self.close_session()

    def update_ip_rep_infos(
        self,
        ip: str,
        country_code: str,
        asn: str,
        asn_org: str,
        list_on: Dict[str, str],
        city: Optional[str] = None,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        country: Optional[str] = None,
        region: Optional[str] = None,
        region_name: Optional[str] = None,
        timezone: Optional[str] = None,
        isp: Optional[str] = None,
        reverse: Optional[str] = None,
        is_proxy: Optional[bool] = None,
        is_hosting: Optional[bool] = None,
    ) -> None:
        """
        Update IP rep stats

        Args:
            ip: IP address
            country_code: IP address country code
            asn: IP address ASN
            asn_org: IP address ASN ORG
            list_on: public lists containing the IP address
            city: City name (optional)
            latitude: Latitude coordinate (optional)
            longitude: Longitude coordinate (optional)
            country: Full country name (optional)
            region: Region code (optional)
            region_name: Region name (optional)
            timezone: Timezone (optional)
            isp: Internet Service Provider (optional)
            reverse: Reverse DNS lookup (optional)
            is_proxy: Whether IP is a proxy (optional)
            is_hosting: Whether IP is a hosting provider (optional)

        """
        session = self.session
        try:
            sanitized_ip = sanitize_ip(ip)
            ip_stats = session.query(IpStats).filter(IpStats.ip == sanitized_ip).first()
            if ip_stats:
                ip_stats.country_code = country_code
                ip_stats.asn = asn
                ip_stats.asn_org = asn_org
                ip_stats.list_on = list_on
                if city:
                    ip_stats.city = city
                if latitude is not None:
                    ip_stats.latitude = latitude
                if longitude is not None:
                    ip_stats.longitude = longitude
                if country:
                    ip_stats.country = country
                if region:
                    ip_stats.region = region
                if region_name:
                    ip_stats.region_name = region_name
                if timezone:
                    ip_stats.timezone = timezone
                if isp:
                    ip_stats.isp = isp
                if reverse:
                    ip_stats.reverse = reverse
                if is_proxy is not None:
                    ip_stats.is_proxy = is_proxy
                if is_hosting is not None:
                    ip_stats.is_hosting = is_hosting
                session.commit()
        except Exception as e:
            session.rollback()
            raise
        finally:
            self.close_session()

    def get_unenriched_ips(self, limit: int = 100) -> List[str]:
        """
        Get IPs that don't have complete reputation data yet.
        Returns IPs without country_code, city, latitude, or longitude data.
        Excludes RFC1918 private addresses and other non-routable IPs.

        Args:
            limit: Maximum number of IPs to return

        Returns:
            List of IP addresses without complete reputation data
        """
        from sqlalchemy.exc import OperationalError

        session = self.session
        try:
            # Try to query including latitude/longitude (for backward compatibility)
            try:
                ips = (
                    session.query(IpStats.ip)
                    .filter(
                        or_(
                            IpStats.country_code.is_(None),
                            IpStats.city.is_(None),
                            IpStats.latitude.is_(None),
                            IpStats.longitude.is_(None),
                        ),
                        ~IpStats.ip.like("10.%"),
                        ~IpStats.ip.like("172.16.%"),
                        ~IpStats.ip.like("172.17.%"),
                        ~IpStats.ip.like("172.18.%"),
                        ~IpStats.ip.like("172.19.%"),
                        ~IpStats.ip.like("172.2_.%"),
                        ~IpStats.ip.like("172.30.%"),
                        ~IpStats.ip.like("172.31.%"),
                        ~IpStats.ip.like("192.168.%"),
                        ~IpStats.ip.like("127.%"),
                        ~IpStats.ip.like("169.254.%"),
                    )
                    .limit(limit)
                    .all()
                )
            except OperationalError as e:
                # If latitude/longitude columns don't exist yet, fall back to old query
                if "no such column" in str(e).lower():
                    ips = (
                        session.query(IpStats.ip)
                        .filter(
                            or_(IpStats.country_code.is_(None), IpStats.city.is_(None)),
                            ~IpStats.ip.like("10.%"),
                            ~IpStats.ip.like("172.16.%"),
                            ~IpStats.ip.like("172.17.%"),
                            ~IpStats.ip.like("172.18.%"),
                            ~IpStats.ip.like("172.19.%"),
                            ~IpStats.ip.like("172.2_.%"),
                            ~IpStats.ip.like("172.30.%"),
                            ~IpStats.ip.like("172.31.%"),
                            ~IpStats.ip.like("192.168.%"),
                            ~IpStats.ip.like("127.%"),
                            ~IpStats.ip.like("169.254.%"),
                        )
                        .limit(limit)
                        .all()
                    )
                else:
                    raise

            return [ip[0] for ip in ips]
        finally:
            self.close_session()

    def get_ips_needing_reevaluation(self) -> List[str]:
        """
        Get all IP addresses that need evaluation.

        Returns:
            List of IP addresses where need_reevaluation is True
            or that have never been analyzed (last_analysis is NULL)
        """
        session = self.session
        try:
            ips = (
                session.query(IpStats.ip)
                .filter(
                    or_(
                        IpStats.need_reevaluation == True,
                        IpStats.last_analysis.is_(None),
                    )
                )
                .all()
            )
            return [ip[0] for ip in ips]
        finally:
            self.close_session()

    def flag_stale_ips_for_reevaluation(self) -> int:
        """
        Flag IPs for reevaluation where:
        - last_seen is newer than the configured retention period
        - last_analysis is more than 5 days ago

        Returns:
            Number of IPs flagged for reevaluation
        """
        from config import get_config

        session = self.session
        try:
            now = datetime.now()
            retention_days = get_config().database_retention_days
            last_seen_cutoff = now - timedelta(days=retention_days)
            last_analysis_cutoff = now - timedelta(days=5)

            count = (
                session.query(IpStats)
                .filter(
                    IpStats.last_seen >= last_seen_cutoff,
                    IpStats.last_analysis <= last_analysis_cutoff,
                    IpStats.need_reevaluation == False,
                    IpStats.manual_category == False,
                )
                .update(
                    {IpStats.need_reevaluation: True},
                    synchronize_session=False,
                )
            )
            session.commit()
            return count
        except Exception as e:
            session.rollback()
            raise

    def flag_all_ips_for_reevaluation(self) -> int:
        """
        Flag ALL IPs for reevaluation, regardless of staleness.
        Skips IPs that have a manual category set.

        Returns:
            Number of IPs flagged for reevaluation
        """
        session = self.session
        try:
            count = (
                session.query(IpStats)
                .filter(
                    IpStats.need_reevaluation == False,
                    IpStats.manual_category == False,
                )
                .update(
                    {IpStats.need_reevaluation: True},
                    synchronize_session=False,
                )
            )
            session.commit()
            return count
        except Exception as e:
            session.rollback()
            raise

    def get_access_logs_paginated(
        self,
        page: int = 1,
        page_size: int = 25,
        ip_filter: Optional[str] = None,
        suspicious_only: bool = False,
        since_minutes: Optional[int] = None,
        sort_order: str = "desc",
    ) -> Dict[str, Any]:
        """
        Retrieve access logs with pagination and optional filtering.

        Args:
            page: Page to retrieve
            page_size: Number of records for page
            ip_filter: Filter by IP address
            suspicious_only: Only return suspicious requests
            since_minutes: Only return logs from the last N minutes
            sort_order: Sort direction for timestamp ('asc' or 'desc')

        Returns:
            List of access log dictionaries
        """
        session = self.session
        try:
            offset = (page - 1) * page_size
            order = (
                AccessLog.timestamp.asc()
                if sort_order == "asc"
                else AccessLog.timestamp.desc()
            )
            query = session.query(AccessLog).order_by(order)

            if ip_filter:
                query = query.filter(AccessLog.ip == sanitize_ip(ip_filter))
            if suspicious_only:
                query = query.filter(AccessLog.is_suspicious == True)
            if since_minutes is not None:
                cutoff_time = datetime.now() - timedelta(minutes=since_minutes)
                query = query.filter(AccessLog.timestamp >= cutoff_time)

            logs = query.offset(offset).limit(page_size).all()
            # Get total count of attackers
            total_access_logs = (
                session.query(AccessLog)
                .filter(AccessLog.ip == sanitize_ip(ip_filter))
                .count()
            )
            total_pages = (total_access_logs + page_size - 1) // page_size

            return {
                "access_logs": [
                    {
                        "id": log.id,
                        "ip": log.ip,
                        "path": log.path,
                        "user_agent": log.user_agent,
                        "method": log.method,
                        "is_suspicious": log.is_suspicious,
                        "is_honeypot_trigger": log.is_honeypot_trigger,
                        "timestamp": log.timestamp.isoformat(),
                        "attack_types": [d.attack_type for d in log.attack_detections],
                    }
                    for log in logs
                ],
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total_logs": total_access_logs,
                    "total_pages": total_pages,
                },
            }
        finally:
            self.close_session()

    def get_access_logs(
        self,
        limit: int = 100,
        offset: int = 0,
        ip_filter: Optional[str] = None,
        suspicious_only: bool = False,
        since_minutes: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve access logs with optional filtering.

        Args:
            limit: Maximum number of records to return
            offset: Number of records to skip
            ip_filter: Filter by IP address
            suspicious_only: Only return suspicious requests
            since_minutes: Only return logs from the last N minutes

        Returns:
            List of access log dictionaries
        """
        session = self.session
        try:
            query = session.query(AccessLog).order_by(AccessLog.timestamp.desc())

            if ip_filter:
                query = query.filter(AccessLog.ip == sanitize_ip(ip_filter))
            if suspicious_only:
                query = query.filter(AccessLog.is_suspicious == True)
            if since_minutes is not None:
                cutoff_time = datetime.now() - timedelta(minutes=since_minutes)
                query = query.filter(AccessLog.timestamp >= cutoff_time)

            logs = query.offset(offset).limit(limit).all()

            return [
                {
                    "id": log.id,
                    "ip": log.ip,
                    "path": log.path,
                    "user_agent": log.user_agent,
                    "method": log.method,
                    "is_suspicious": log.is_suspicious,
                    "is_honeypot_trigger": log.is_honeypot_trigger,
                    "timestamp": log.timestamp.isoformat(),
                    "attack_types": [d.attack_type for d in log.attack_detections],
                }
                for log in logs
            ]
        finally:
            self.close_session()

    def get_credential_attempts(
        self, limit: int = 100, offset: int = 0, ip_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve credential attempts with optional filtering.

        Args:
            limit: Maximum number of records to return
            offset: Number of records to skip
            ip_filter: Filter by IP address

        Returns:
            List of credential attempt dictionaries
        """
        session = self.session
        try:
            query = session.query(CredentialAttempt).order_by(
                CredentialAttempt.timestamp.desc()
            )

            if ip_filter:
                query = query.filter(CredentialAttempt.ip == sanitize_ip(ip_filter))

            attempts = query.offset(offset).limit(limit).all()

            return [
                {
                    "id": attempt.id,
                    "ip": attempt.ip,
                    "path": attempt.path,
                    "username": attempt.username,
                    "password": attempt.password,
                    "timestamp": attempt.timestamp.isoformat(),
                }
                for attempt in attempts
            ]
        finally:
            self.close_session()

    def get_ip_stats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve IP statistics ordered by total requests.

        Args:
            limit: Maximum number of records to return

        Returns:
            List of IP stats dictionaries
        """
        session = self.session
        try:
            stats = (
                session.query(IpStats)
                .order_by(IpStats.total_requests.desc())
                .limit(limit)
                .all()
            )

            return [
                {
                    "ip": s.ip,
                    "total_requests": s.total_requests,
                    "first_seen": s.first_seen.isoformat() if s.first_seen else None,
                    "last_seen": s.last_seen.isoformat() if s.last_seen else None,
                    "country_code": s.country_code,
                    "city": s.city,
                    "asn": s.asn,
                    "asn_org": s.asn_org,
                    "reputation_score": s.reputation_score,
                    "reputation_source": s.reputation_source,
                    "analyzed_metrics": s.analyzed_metrics,
                    "category": s.category,
                    "manual_category": s.manual_category,
                    "last_analysis": (
                        s.last_analysis.isoformat() if s.last_analysis else None
                    ),
                }
                for s in stats
            ]
        finally:
            self.close_session()

    def get_ip_stats_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve IP statistics for a specific IP address.

        Args:
            ip: The IP address to look up

        Returns:
            Dictionary with IP stats or None if not found
        """
        session = self.session
        try:
            stat = session.query(IpStats).filter(IpStats.ip == ip).first()

            if not stat:
                return None

            # Get category history for this IP
            category_history = self.get_category_history(ip)

            return {
                "ip": stat.ip,
                "total_requests": stat.total_requests,
                "first_seen": stat.first_seen.isoformat() if stat.first_seen else None,
                "last_seen": stat.last_seen.isoformat() if stat.last_seen else None,
                "country_code": stat.country_code,
                "city": stat.city,
                "country": stat.country,
                "region": stat.region,
                "region_name": stat.region_name,
                "timezone": stat.timezone,
                "latitude": stat.latitude,
                "longitude": stat.longitude,
                "isp": stat.isp,
                "reverse": stat.reverse,
                "asn": stat.asn,
                "asn_org": stat.asn_org,
                "is_proxy": stat.is_proxy,
                "is_hosting": stat.is_hosting,
                "list_on": stat.list_on or {},
                "reputation_score": stat.reputation_score,
                "reputation_source": stat.reputation_source,
                "analyzed_metrics": stat.analyzed_metrics or {},
                "category": stat.category,
                "category_scores": stat.category_scores or {},
                "manual_category": stat.manual_category,
                "last_analysis": (
                    stat.last_analysis.isoformat() if stat.last_analysis else None
                ),
                "category_history": category_history,
            }
        finally:
            self.close_session()

    def get_attackers_paginated(
        self,
        page: int = 1,
        page_size: int = 25,
        sort_by: str = "total_requests",
        sort_order: str = "desc",
    ) -> Dict[str, Any]:
        """
        Retrieve paginated list of attacker IPs ordered by specified field.

        Args:
            page: Page number (1-indexed)
            page_size: Number of results per page
            sort_by: Field to sort by (total_requests, first_seen, last_seen)
            sort_order: Sort order (asc or desc)

        Returns:
            Dictionary with attackers list and pagination info
        """
        session = self.session
        try:
            offset = (page - 1) * page_size

            # Validate sort parameters
            valid_sort_fields = {"total_requests", "first_seen", "last_seen"}
            sort_by = sort_by if sort_by in valid_sort_fields else "total_requests"
            sort_order = (
                sort_order.lower() if sort_order.lower() in {"asc", "desc"} else "desc"
            )

            # Get total count of attackers
            total_attackers = (
                session.query(IpStats).filter(IpStats.category == "attacker").count()
            )

            # Build query with sorting
            query = session.query(IpStats).filter(IpStats.category == "attacker")

            if sort_by == "total_requests":
                query = query.order_by(
                    IpStats.total_requests.desc()
                    if sort_order == "desc"
                    else IpStats.total_requests.asc()
                )
            elif sort_by == "first_seen":
                query = query.order_by(
                    IpStats.first_seen.desc()
                    if sort_order == "desc"
                    else IpStats.first_seen.asc()
                )
            elif sort_by == "last_seen":
                query = query.order_by(
                    IpStats.last_seen.desc()
                    if sort_order == "desc"
                    else IpStats.last_seen.asc()
                )

            # Get paginated attackers
            attackers = query.offset(offset).limit(page_size).all()

            total_pages = (total_attackers + page_size - 1) // page_size

            return {
                "attackers": [
                    {
                        "ip": a.ip,
                        "total_requests": a.total_requests,
                        "first_seen": (
                            a.first_seen.isoformat() if a.first_seen else None
                        ),
                        "last_seen": a.last_seen.isoformat() if a.last_seen else None,
                        "country_code": a.country_code,
                        "city": a.city,
                        "latitude": a.latitude,
                        "longitude": a.longitude,
                        "asn": a.asn,
                        "asn_org": a.asn_org,
                        "reputation_score": a.reputation_score,
                        "reputation_source": a.reputation_source,
                        "category": a.category,
                        "category_scores": a.category_scores or {},
                    }
                    for a in attackers
                ],
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total_attackers": total_attackers,
                    "total_pages": total_pages,
                },
            }
        finally:
            self.close_session()

    def get_all_ips_paginated(
        self,
        page: int = 1,
        page_size: int = 25,
        sort_by: str = "total_requests",
        sort_order: str = "desc",
        categories: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve paginated list of all IPs (or filtered by categories) ordered by specified field.

        Args:
            page: Page number (1-indexed)
            page_size: Number of results per page
            sort_by: Field to sort by (total_requests, first_seen, last_seen)
            sort_order: Sort order (asc or desc)
            categories: Optional list of categories to filter by

        Returns:
            Dictionary with IPs list and pagination info
        """
        session = self.session
        try:
            offset = (page - 1) * page_size

            # Validate sort parameters
            valid_sort_fields = {"total_requests", "first_seen", "last_seen"}
            sort_by = sort_by if sort_by in valid_sort_fields else "total_requests"
            sort_order = (
                sort_order.lower() if sort_order.lower() in {"asc", "desc"} else "desc"
            )

            # Build query with optional category filter
            query = session.query(IpStats)
            if categories:
                query = query.filter(IpStats.category.in_(categories))

            # Get total count
            total_ips = query.count()

            # Apply sorting
            if sort_by == "total_requests":
                query = query.order_by(
                    IpStats.total_requests.desc()
                    if sort_order == "desc"
                    else IpStats.total_requests.asc()
                )
            elif sort_by == "first_seen":
                query = query.order_by(
                    IpStats.first_seen.desc()
                    if sort_order == "desc"
                    else IpStats.first_seen.asc()
                )
            elif sort_by == "last_seen":
                query = query.order_by(
                    IpStats.last_seen.desc()
                    if sort_order == "desc"
                    else IpStats.last_seen.asc()
                )

            # Get paginated IPs
            ips = query.offset(offset).limit(page_size).all()

            total_pages = (total_ips + page_size - 1) // page_size

            return {
                "ips": [
                    {
                        "ip": ip.ip,
                        "total_requests": ip.total_requests,
                        "first_seen": (
                            ip.first_seen.isoformat() if ip.first_seen else None
                        ),
                        "last_seen": ip.last_seen.isoformat() if ip.last_seen else None,
                        "country_code": ip.country_code,
                        "city": ip.city,
                        "latitude": ip.latitude,
                        "longitude": ip.longitude,
                        "asn": ip.asn,
                        "asn_org": ip.asn_org,
                        "reputation_score": ip.reputation_score,
                        "reputation_source": ip.reputation_source,
                        "category": ip.category,
                        "category_scores": ip.category_scores or {},
                    }
                    for ip in ips
                ],
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": total_ips,
                    "total_pages": total_pages,
                },
            }
        finally:
            self.close_session()

    def _public_ip_filter(self, query, ip_column, server_ip: Optional[str] = None):
        """Apply SQL-level filters to exclude local/private IPs and server IP."""
        query = query.filter(
            ~ip_column.like("10.%"),
            ~ip_column.like("172.16.%"),
            ~ip_column.like("172.17.%"),
            ~ip_column.like("172.18.%"),
            ~ip_column.like("172.19.%"),
            ~ip_column.like("172.2_.%"),
            ~ip_column.like("172.30.%"),
            ~ip_column.like("172.31.%"),
            ~ip_column.like("192.168.%"),
            ~ip_column.like("127.%"),
            ~ip_column.like("0.%"),
            ~ip_column.like("169.254.%"),
            ip_column != "::1",
        )
        if server_ip:
            query = query.filter(ip_column != server_ip)
        return query

    def get_dashboard_counts(self) -> Dict[str, int]:
        """
        Get aggregate statistics for the dashboard (excludes local/private IPs and server IP).

        Returns:
            Dictionary with total_accesses, unique_ips, unique_paths,
            suspicious_accesses, honeypot_triggered, honeypot_ips
        """
        session = self.session
        try:
            from config import get_config

            config = get_config()
            server_ip = config.get_server_ip()

            # Single aggregation query instead of loading all rows
            base = session.query(
                func.count(AccessLog.id).label("total_accesses"),
                func.count(distinct(AccessLog.ip)).label("unique_ips"),
                func.count(distinct(AccessLog.path)).label("unique_paths"),
                func.count(case((AccessLog.is_suspicious == True, 1))).label(
                    "suspicious_accesses"
                ),
                func.count(case((AccessLog.is_honeypot_trigger == True, 1))).label(
                    "honeypot_triggered"
                ),
            )
            base = self._public_ip_filter(base, AccessLog.ip, server_ip)
            row = base.one()

            # Honeypot unique IPs (separate query for distinct on filtered subset)
            hp_query = session.query(func.count(distinct(AccessLog.ip))).filter(
                AccessLog.is_honeypot_trigger == True
            )
            hp_query = self._public_ip_filter(hp_query, AccessLog.ip, server_ip)
            honeypot_ips = hp_query.scalar() or 0

            unique_attackers = (
                session.query(IpStats).filter(IpStats.category == "attacker").count()
            )

            return {
                "total_accesses": row.total_accesses or 0,
                "unique_ips": row.unique_ips or 0,
                "unique_paths": row.unique_paths or 0,
                "suspicious_accesses": row.suspicious_accesses or 0,
                "honeypot_triggered": row.honeypot_triggered or 0,
                "honeypot_ips": honeypot_ips,
                "unique_attackers": unique_attackers,
            }
        finally:
            self.close_session()

    def get_top_ips(self, limit: int = 10) -> List[tuple]:
        """
        Get top IP addresses by access count (excludes local/private IPs and server IP).

        Args:
            limit: Maximum number of results

        Returns:
            List of (ip, count) tuples ordered by count descending
        """
        session = self.session
        try:
            from config import get_config

            config = get_config()
            server_ip = config.get_server_ip()

            query = session.query(IpStats.ip, IpStats.total_requests)
            query = self._public_ip_filter(query, IpStats.ip, server_ip)
            results = query.order_by(IpStats.total_requests.desc()).limit(limit).all()

            return [(row.ip, row.total_requests) for row in results]
        finally:
            self.close_session()

    def get_top_paths(self, limit: int = 10) -> List[tuple]:
        """
        Get top paths by access count.

        Args:
            limit: Maximum number of results

        Returns:
            List of (path, count) tuples ordered by count descending
        """
        session = self.session
        try:
            results = (
                session.query(AccessLog.path, func.count(AccessLog.id).label("count"))
                .group_by(AccessLog.path)
                .order_by(func.count(AccessLog.id).desc())
                .limit(limit)
                .all()
            )

            return [(row.path, row.count) for row in results]
        finally:
            self.close_session()

    def get_top_user_agents(self, limit: int = 10) -> List[tuple]:
        """
        Get top user agents by access count.

        Args:
            limit: Maximum number of results

        Returns:
            List of (user_agent, count) tuples ordered by count descending
        """
        session = self.session
        try:
            results = (
                session.query(
                    AccessLog.user_agent, func.count(AccessLog.id).label("count")
                )
                .filter(AccessLog.user_agent.isnot(None), AccessLog.user_agent != "")
                .group_by(AccessLog.user_agent)
                .order_by(func.count(AccessLog.id).desc())
                .limit(limit)
                .all()
            )

            return [(row.user_agent, row.count) for row in results]
        finally:
            self.close_session()

    def get_recent_suspicious(self, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Get recent suspicious access attempts (excludes local/private IPs and server IP).

        Args:
            limit: Maximum number of results

        Returns:
            List of access log dictionaries with is_suspicious=True
        """
        session = self.session
        try:
            from config import get_config

            config = get_config()
            server_ip = config.get_server_ip()

            query = (
                session.query(AccessLog)
                .filter(AccessLog.is_suspicious == True)
                .order_by(AccessLog.timestamp.desc())
            )
            query = self._public_ip_filter(query, AccessLog.ip, server_ip)
            logs = query.limit(limit).all()

            return [
                {
                    "ip": log.ip,
                    "path": log.path,
                    "user_agent": log.user_agent,
                    "timestamp": log.timestamp.isoformat(),
                    "log_id": log.id,
                }
                for log in logs
            ]
        finally:
            self.close_session()

    def get_honeypot_triggered_ips(self) -> List[tuple]:
        """
        Get IPs that triggered honeypot paths with the paths they accessed
        (excludes local/private IPs and server IP).

        Returns:
            List of (ip, [paths]) tuples
        """
        session = self.session
        try:
            # Get server IP to filter it out
            from config import get_config

            config = get_config()
            server_ip = config.get_server_ip()

            # Get all honeypot triggers grouped by IP
            results = (
                session.query(AccessLog.ip, AccessLog.path)
                .filter(AccessLog.is_honeypot_trigger == True)
                .all()
            )

            # Group paths by IP, filtering out local/private IPs and server IP
            ip_paths: Dict[str, List[str]] = {}
            for row in results:
                # Skip invalid IPs
                if not is_valid_public_ip(row.ip, server_ip):
                    continue
                if row.ip not in ip_paths:
                    ip_paths[row.ip] = []
                if row.path not in ip_paths[row.ip]:
                    ip_paths[row.ip].append(row.path)

            return [(ip, paths) for ip, paths in ip_paths.items()]
        finally:
            self.close_session()

    def get_recent_attacks(self, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Get recent access logs that have attack detections.

        Args:
            limit: Maximum number of results

        Returns:
            List of access log dicts with attack_types included
        """
        session = self.session
        try:
            # Get access logs that have attack detections
            logs = (
                session.query(AccessLog)
                .join(AttackDetection)
                .order_by(AccessLog.timestamp.desc())
                .limit(limit)
                .all()
            )

            return [
                {
                    "ip": log.ip,
                    "path": log.path,
                    "user_agent": log.user_agent,
                    "timestamp": log.timestamp.isoformat(),
                    "attack_types": [d.attack_type for d in log.attack_detections],
                }
                for log in logs
            ]
        finally:
            self.close_session()

    def get_honeypot_paginated(
        self,
        page: int = 1,
        page_size: int = 5,
        sort_by: str = "count",
        sort_order: str = "desc",
    ) -> Dict[str, Any]:
        """
        Retrieve paginated list of honeypot-triggered IPs with their paths.

        Args:
            page: Page number (1-indexed)
            page_size: Number of results per page
            sort_by: Field to sort by (count or ip)
            sort_order: Sort order (asc or desc)

        Returns:
            Dictionary with honeypots list and pagination info
        """
        session = self.session
        try:
            from config import get_config

            config = get_config()
            server_ip = config.get_server_ip()

            offset = (page - 1) * page_size

            # Count distinct paths per IP using SQL GROUP BY
            count_col = func.count(distinct(AccessLog.path)).label("path_count")
            base_query = session.query(AccessLog.ip, count_col).filter(
                AccessLog.is_honeypot_trigger == True
            )
            base_query = self._public_ip_filter(base_query, AccessLog.ip, server_ip)
            base_query = base_query.group_by(AccessLog.ip)

            # Get total count of distinct honeypot IPs
            total_honeypots = base_query.count()

            # Apply sorting
            if sort_by == "count":
                order_expr = (
                    count_col.desc() if sort_order == "desc" else count_col.asc()
                )
            else:
                order_expr = (
                    AccessLog.ip.desc() if sort_order == "desc" else AccessLog.ip.asc()
                )

            ip_rows = (
                base_query.order_by(order_expr).offset(offset).limit(page_size).all()
            )

            # Fetch distinct paths only for the paginated IPs
            paginated_ips = [row.ip for row in ip_rows]
            honeypot_list = []
            if paginated_ips:
                path_rows = (
                    session.query(AccessLog.ip, AccessLog.path)
                    .filter(
                        AccessLog.is_honeypot_trigger == True,
                        AccessLog.ip.in_(paginated_ips),
                    )
                    .distinct(AccessLog.ip, AccessLog.path)
                    .all()
                )
                ip_paths: Dict[str, List[str]] = {}
                for row in path_rows:
                    ip_paths.setdefault(row.ip, []).append(row.path)

                # Preserve the order from the sorted query
                for row in ip_rows:
                    paths = ip_paths.get(row.ip, [])
                    honeypot_list.append(
                        {"ip": row.ip, "paths": paths, "count": row.path_count}
                    )

            total_pages = max(1, (total_honeypots + page_size - 1) // page_size)

            return {
                "honeypots": honeypot_list,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": total_honeypots,
                    "total_pages": total_pages,
                },
            }
        finally:
            self.close_session()

    def get_credentials_paginated(
        self,
        page: int = 1,
        page_size: int = 5,
        sort_by: str = "timestamp",
        sort_order: str = "desc",
    ) -> Dict[str, Any]:
        """
        Retrieve paginated list of credential attempts.

        Args:
            page: Page number (1-indexed)
            page_size: Number of results per page
            sort_by: Field to sort by (timestamp, ip, username)
            sort_order: Sort order (asc or desc)

        Returns:
            Dictionary with credentials list and pagination info
        """
        session = self.session
        try:
            offset = (page - 1) * page_size

            # Validate sort parameters
            valid_sort_fields = {"timestamp", "ip", "username"}
            sort_by = sort_by if sort_by in valid_sort_fields else "timestamp"
            sort_order = (
                sort_order.lower() if sort_order.lower() in {"asc", "desc"} else "desc"
            )

            total_credentials = session.query(CredentialAttempt).count()

            # Build query with sorting
            query = session.query(CredentialAttempt)

            if sort_by == "timestamp":
                query = query.order_by(
                    CredentialAttempt.timestamp.desc()
                    if sort_order == "desc"
                    else CredentialAttempt.timestamp.asc()
                )
            elif sort_by == "ip":
                query = query.order_by(
                    CredentialAttempt.ip.desc()
                    if sort_order == "desc"
                    else CredentialAttempt.ip.asc()
                )
            elif sort_by == "username":
                query = query.order_by(
                    CredentialAttempt.username.desc()
                    if sort_order == "desc"
                    else CredentialAttempt.username.asc()
                )

            credentials = query.offset(offset).limit(page_size).all()
            total_pages = (total_credentials + page_size - 1) // page_size

            return {
                "credentials": [
                    {
                        "ip": c.ip,
                        "username": c.username,
                        "password": c.password,
                        "path": c.path,
                        "timestamp": c.timestamp.isoformat() if c.timestamp else None,
                    }
                    for c in credentials
                ],
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": total_credentials,
                    "total_pages": total_pages,
                },
            }
        finally:
            self.close_session()

    def get_top_ips_paginated(
        self,
        page: int = 1,
        page_size: int = 5,
        sort_by: str = "count",
        sort_order: str = "desc",
    ) -> Dict[str, Any]:
        """
        Retrieve paginated list of top IP addresses by access count.

        Uses the IpStats table (which already stores total_requests per IP)
        instead of doing a costly GROUP BY on the large access_logs table.

        Args:
            page: Page number (1-indexed)
            page_size: Number of results per page
            sort_by: Field to sort by (count or ip)
            sort_order: Sort order (asc or desc)

        Returns:
            Dictionary with IPs list and pagination info
        """
        session = self.session
        try:
            from config import get_config

            config = get_config()
            server_ip = config.get_server_ip()

            offset = (page - 1) * page_size

            base_query = session.query(IpStats)
            base_query = self._public_ip_filter(base_query, IpStats.ip, server_ip)

            total_ips = base_query.count()

            if sort_by == "count":
                order_col = IpStats.total_requests
            else:
                order_col = IpStats.ip

            if sort_order == "desc":
                base_query = base_query.order_by(order_col.desc())
            else:
                base_query = base_query.order_by(order_col.asc())

            results = base_query.offset(offset).limit(page_size).all()

            total_pages = max(1, (total_ips + page_size - 1) // page_size)

            return {
                "ips": [
                    {
                        "ip": row.ip,
                        "count": row.total_requests,
                        "category": row.category or "unknown",
                    }
                    for row in results
                ],
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": total_ips,
                    "total_pages": total_pages,
                },
            }
        finally:
            self.close_session()

    def get_top_paths_paginated(
        self,
        page: int = 1,
        page_size: int = 5,
        sort_by: str = "count",
        sort_order: str = "desc",
    ) -> Dict[str, Any]:
        """
        Retrieve paginated list of top paths by access count.

        Args:
            page: Page number (1-indexed)
            page_size: Number of results per page
            sort_by: Field to sort by (count or path)
            sort_order: Sort order (asc or desc)

        Returns:
            Dictionary with paths list and pagination info
        """
        session = self.session
        try:
            offset = (page - 1) * page_size

            count_col = func.count(AccessLog.id).label("count")

            # Get total number of distinct paths
            total_paths = (
                session.query(func.count(distinct(AccessLog.path))).scalar() or 0
            )

            # Build query with SQL-level sorting and pagination
            query = session.query(AccessLog.path, count_col).group_by(AccessLog.path)

            if sort_by == "count":
                order_expr = (
                    count_col.desc() if sort_order == "desc" else count_col.asc()
                )
            else:
                order_expr = (
                    AccessLog.path.desc()
                    if sort_order == "desc"
                    else AccessLog.path.asc()
                )

            results = query.order_by(order_expr).offset(offset).limit(page_size).all()
            total_pages = max(1, (total_paths + page_size - 1) // page_size)

            return {
                "paths": [{"path": row.path, "count": row.count} for row in results],
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": total_paths,
                    "total_pages": total_pages,
                },
            }
        finally:
            self.close_session()

    def get_top_user_agents_paginated(
        self,
        page: int = 1,
        page_size: int = 5,
        sort_by: str = "count",
        sort_order: str = "desc",
    ) -> Dict[str, Any]:
        """
        Retrieve paginated list of top user agents by access count.

        Args:
            page: Page number (1-indexed)
            page_size: Number of results per page
            sort_by: Field to sort by (count or user_agent)
            sort_order: Sort order (asc or desc)

        Returns:
            Dictionary with user agents list and pagination info
        """
        session = self.session
        try:
            offset = (page - 1) * page_size

            count_col = func.count(AccessLog.id).label("count")

            base_filter = [AccessLog.user_agent.isnot(None), AccessLog.user_agent != ""]

            # Get total number of distinct user agents
            total_uas = (
                session.query(func.count(distinct(AccessLog.user_agent)))
                .filter(*base_filter)
                .scalar()
                or 0
            )

            # Build query with SQL-level sorting and pagination
            query = (
                session.query(AccessLog.user_agent, count_col)
                .filter(*base_filter)
                .group_by(AccessLog.user_agent)
            )

            if sort_by == "count":
                order_expr = (
                    count_col.desc() if sort_order == "desc" else count_col.asc()
                )
            else:
                order_expr = (
                    AccessLog.user_agent.desc()
                    if sort_order == "desc"
                    else AccessLog.user_agent.asc()
                )

            results = query.order_by(order_expr).offset(offset).limit(page_size).all()
            total_pages = max(1, (total_uas + page_size - 1) // page_size)

            return {
                "user_agents": [
                    {"user_agent": row.user_agent, "count": row.count}
                    for row in results
                ],
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": total_uas,
                    "total_pages": total_pages,
                },
            }
        finally:
            self.close_session()

    def get_attack_types_paginated(
        self,
        page: int = 1,
        page_size: int = 5,
        sort_by: str = "timestamp",
        sort_order: str = "desc",
        ip_filter: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve paginated list of detected attack types with access logs.

        Args:
            page: Page number (1-indexed)
            page_size: Number of results per page
            sort_by: Field to sort by (timestamp, ip, attack_type)
            sort_order: Sort order (asc or desc)
            ip_filter: Optional IP address to filter results

        Returns:
            Dictionary with attacks list and pagination info
        """
        session = self.session
        try:
            offset = (page - 1) * page_size

            # Validate sort parameters
            valid_sort_fields = {"timestamp", "ip", "attack_type"}
            sort_by = sort_by if sort_by in valid_sort_fields else "timestamp"
            sort_order = (
                sort_order.lower() if sort_order.lower() in {"asc", "desc"} else "desc"
            )

            # Base query filter
            base_filters = []
            if ip_filter:
                base_filters.append(AccessLog.ip == ip_filter)

            # Count total unique access logs with attack detections
            count_query = session.query(AccessLog).join(AttackDetection)
            if base_filters:
                count_query = count_query.filter(*base_filters)
            total_attacks = count_query.distinct(AccessLog.id).count()

            # Get paginated access logs with attack detections
            query = session.query(AccessLog).join(AttackDetection)
            if base_filters:
                query = query.filter(*base_filters)
            query = query.distinct(AccessLog.id)

            if sort_by == "timestamp":
                query = query.order_by(
                    AccessLog.timestamp.desc()
                    if sort_order == "desc"
                    else AccessLog.timestamp.asc()
                )
            elif sort_by == "ip":
                query = query.order_by(
                    AccessLog.ip.desc() if sort_order == "desc" else AccessLog.ip.asc()
                )

            # Apply LIMIT and OFFSET at database level
            logs = query.offset(offset).limit(page_size).all()

            # Convert to attack list (exclude raw_request for performance - it's too large)
            paginated = [
                {
                    "id": log.id,
                    "ip": log.ip,
                    "path": log.path,
                    "user_agent": log.user_agent,
                    "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                    "attack_types": [d.attack_type for d in log.attack_detections],
                    "raw_request": log.raw_request,  # Keep for backward compatibility
                }
                for log in logs
            ]

            total_pages = (total_attacks + page_size - 1) // page_size

            return {
                "attacks": paginated,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": total_attacks,
                    "total_pages": total_pages,
                },
            }
        finally:
            self.close_session()

    def get_raw_request_by_id(self, log_id: int) -> Optional[str]:
        """
        Retrieve raw HTTP request for a specific access log ID.

        Args:
            log_id: The access log ID

        Returns:
            The raw request string, or None if not found or not available
        """
        session = self.session
        try:
            access_log = session.query(AccessLog).filter(AccessLog.id == log_id).first()
            if access_log:
                return access_log.raw_request
            return None
        finally:
            self.close_session()

    def get_attack_types_stats(
        self, limit: int = 20, ip_filter: str | None = None
    ) -> Dict[str, Any]:
        """
        Get aggregated statistics for attack types (efficient for large datasets).

        Args:
            limit: Maximum number of attack types to return
            ip_filter: Optional IP address to filter results for

        Returns:
            Dictionary with attack type counts
        """
        session = self.session
        try:
            from sqlalchemy import func

            # Aggregate attack types with count
            query = session.query(
                AttackDetection.attack_type,
                func.count(AttackDetection.id).label("count"),
            )

            if ip_filter:
                query = query.join(
                    AccessLog, AttackDetection.access_log_id == AccessLog.id
                ).filter(AccessLog.ip == ip_filter)

            results = (
                query.group_by(AttackDetection.attack_type)
                .order_by(func.count(AttackDetection.id).desc())
                .limit(limit)
                .all()
            )

            return {
                "attack_types": [
                    {"type": row.attack_type, "count": row.count} for row in results
                ]
            }
        finally:
            self.close_session()

    def search_attacks_and_ips(
        self,
        query: str,
        page: int = 1,
        page_size: int = 20,
    ) -> Dict[str, Any]:
        """
        Search attacks and IPs matching a query string.

        Searches across AttackDetection (attack_type, matched_pattern),
        AccessLog (ip, path), and IpStats (ip, city, country, isp, asn_org).

        Args:
            query: Search term (partial match)
            page: Page number (1-indexed)
            page_size: Results per page

        Returns:
            Dictionary with matching attacks, ips, and pagination info
        """
        session = self.session
        try:
            offset = (page - 1) * page_size
            like_q = f"%{query}%"

            # --- Search attacks (AccessLog + AttackDetection) ---
            attack_query = (
                session.query(AccessLog)
                .join(AttackDetection)
                .filter(
                    or_(
                        AccessLog.ip.ilike(like_q),
                        AccessLog.path.ilike(like_q),
                        AttackDetection.attack_type.ilike(like_q),
                        AttackDetection.matched_pattern.ilike(like_q),
                    )
                )
                .distinct(AccessLog.id)
            )

            total_attacks = attack_query.count()
            attack_logs = (
                attack_query.order_by(AccessLog.timestamp.desc())
                .offset(offset)
                .limit(page_size)
                .all()
            )

            attacks = [
                {
                    "id": log.id,
                    "ip": log.ip,
                    "path": log.path,
                    "user_agent": log.user_agent,
                    "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                    "attack_types": [d.attack_type for d in log.attack_detections],
                    "log_id": log.id,
                }
                for log in attack_logs
            ]

            # --- Search IPs (IpStats) ---
            ip_query = session.query(IpStats).filter(
                or_(
                    IpStats.ip.ilike(like_q),
                    IpStats.city.ilike(like_q),
                    IpStats.country.ilike(like_q),
                    IpStats.country_code.ilike(like_q),
                    IpStats.isp.ilike(like_q),
                    IpStats.asn_org.ilike(like_q),
                    IpStats.reverse.ilike(like_q),
                )
            )

            total_ips = ip_query.count()
            ips = (
                ip_query.order_by(IpStats.total_requests.desc())
                .offset(offset)
                .limit(page_size)
                .all()
            )

            ip_results = [
                {
                    "ip": stat.ip,
                    "total_requests": stat.total_requests,
                    "first_seen": (
                        stat.first_seen.isoformat() if stat.first_seen else None
                    ),
                    "last_seen": stat.last_seen.isoformat() if stat.last_seen else None,
                    "country_code": stat.country_code,
                    "city": stat.city,
                    "category": stat.category,
                    "isp": stat.isp,
                    "asn_org": stat.asn_org,
                }
                for stat in ips
            ]

            total = total_attacks + total_ips
            total_pages = max(
                1, (max(total_attacks, total_ips) + page_size - 1) // page_size
            )

            return {
                "attacks": attacks,
                "ips": ip_results,
                "query": query,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total_attacks": total_attacks,
                    "total_ips": total_ips,
                    "total": total,
                    "total_pages": total_pages,
                },
            }
        finally:
            self.close_session()


# Module-level singleton instance
_db_manager = DatabaseManager()


def get_database() -> DatabaseManager:
    """Get the database manager singleton instance."""
    return _db_manager


def initialize_database(database_path: str = "data/krawl.db") -> None:
    """Initialize the database system."""
    _db_manager.initialize(database_path)
