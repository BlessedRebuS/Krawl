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

from sqlalchemy import create_engine, func, distinct, case, event
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

        # Set restrictive file permissions (owner read/write only)
        if os.path.exists(database_path):
            try:
                os.chmod(database_path, stat.S_IRUSR | stat.S_IWUSR)  # 600
            except OSError:
                # May fail on some systems, not critical
                pass

        self._initialized = True

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
            self._update_ip_stats(session, ip)

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

    def _update_ip_stats(self, session: Session, ip: str) -> None:
        """
        Update IP statistics (upsert pattern).

        Args:
            session: Active database session
            ip: IP address to update
        """
        sanitized_ip = sanitize_ip(ip)
        now = datetime.now()

        ip_stats = session.query(IpStats).filter(IpStats.ip == sanitized_ip).first()

        if ip_stats:
            ip_stats.total_requests += 1
            ip_stats.last_seen = now
        else:
            ip_stats = IpStats(
                ip=sanitized_ip, total_requests=1, first_seen=now, last_seen=now
            )
            session.add(ip_stats)

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
        Only records if there's an actual change from a previous category.

        Args:
            ip: IP address
            old_category: Previous category (None if first categorization)
            new_category: New category
            timestamp: When the change occurred
        """
        # Don't record initial categorization (when old_category is None)
        # Only record actual category changes
        if old_category is None:
            return

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
    ) -> None:
        """
        Update IP rep stats

        Args:
            ip: IP address
            country_code: IP address country code
            asn: IP address ASN
            asn_org: IP address ASN ORG
            list_on: public lists containing the IP address

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
                session.commit()
        except Exception as e:
            session.rollback()
            raise
        finally:
            self.close_session()

    def get_unenriched_ips(self, limit: int = 100) -> List[str]:
        """
        Get IPs that don't have reputation data yet.
        Excludes RFC1918 private addresses and other non-routable IPs.

        Args:
            limit: Maximum number of IPs to return

        Returns:
            List of IP addresses without reputation data
        """
        session = self.session
        try:
            ips = (
                session.query(IpStats.ip)
                .filter(
                    IpStats.country_code.is_(None),
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
            return [ip[0] for ip in ips]
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
                "asn": stat.asn,
                "asn_org": stat.asn_org,
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

    def get_dashboard_counts(self) -> Dict[str, int]:
        """
        Get aggregate statistics for the dashboard (excludes local/private IPs and server IP).

        Returns:
            Dictionary with total_accesses, unique_ips, unique_paths,
            suspicious_accesses, honeypot_triggered, honeypot_ips
        """
        session = self.session
        try:
            # Get server IP to filter it out
            from config import get_config

            config = get_config()
            server_ip = config.get_server_ip()

            # Get all accesses first, then filter out local IPs and server IP
            all_accesses = session.query(AccessLog).all()

            # Filter out local/private IPs and server IP
            public_accesses = [
                log for log in all_accesses if is_valid_public_ip(log.ip, server_ip)
            ]

            # Calculate counts from filtered data
            total_accesses = len(public_accesses)
            unique_ips = len(set(log.ip for log in public_accesses))
            unique_paths = len(set(log.path for log in public_accesses))
            suspicious_accesses = sum(1 for log in public_accesses if log.is_suspicious)
            honeypot_triggered = sum(
                1 for log in public_accesses if log.is_honeypot_trigger
            )
            honeypot_ips = len(
                set(log.ip for log in public_accesses if log.is_honeypot_trigger)
            )

            # Count unique attackers from IpStats (matching the "Attackers by Total Requests" table)
            unique_attackers = (
                session.query(IpStats).filter(IpStats.category == "attacker").count()
            )

            return {
                "total_accesses": total_accesses,
                "unique_ips": unique_ips,
                "unique_paths": unique_paths,
                "suspicious_accesses": suspicious_accesses,
                "honeypot_triggered": honeypot_triggered,
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
            # Get server IP to filter it out
            from config import get_config

            config = get_config()
            server_ip = config.get_server_ip()

            results = (
                session.query(AccessLog.ip, func.count(AccessLog.id).label("count"))
                .group_by(AccessLog.ip)
                .order_by(func.count(AccessLog.id).desc())
                .all()
            )

            # Filter out local/private IPs and server IP, then limit results
            filtered = [
                (row.ip, row.count)
                for row in results
                if is_valid_public_ip(row.ip, server_ip)
            ]
            return filtered[:limit]
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
            # Get server IP to filter it out
            from config import get_config

            config = get_config()
            server_ip = config.get_server_ip()

            logs = (
                session.query(AccessLog)
                .filter(AccessLog.is_suspicious == True)
                .order_by(AccessLog.timestamp.desc())
                .all()
            )

            # Filter out local/private IPs and server IP
            filtered_logs = [
                log for log in logs if is_valid_public_ip(log.ip, server_ip)
            ]

            return [
                {
                    "ip": log.ip,
                    "path": log.path,
                    "user_agent": log.user_agent,
                    "timestamp": log.timestamp.isoformat(),
                }
                for log in filtered_logs[:limit]
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

            # Get honeypot triggers grouped by IP
            results = (
                session.query(AccessLog.ip, AccessLog.path)
                .filter(AccessLog.is_honeypot_trigger == True)
                .all()
            )

            # Group paths by IP, filtering out invalid IPs
            ip_paths: Dict[str, List[str]] = {}
            for row in results:
                if not is_valid_public_ip(row.ip, server_ip):
                    continue
                if row.ip not in ip_paths:
                    ip_paths[row.ip] = []
                if row.path not in ip_paths[row.ip]:
                    ip_paths[row.ip].append(row.path)

            # Create list and sort
            honeypot_list = [
                {"ip": ip, "paths": paths, "count": len(paths)}
                for ip, paths in ip_paths.items()
            ]

            if sort_by == "count":
                honeypot_list.sort(
                    key=lambda x: x["count"], reverse=(sort_order == "desc")
                )
            else:  # sort by ip
                honeypot_list.sort(
                    key=lambda x: x["ip"], reverse=(sort_order == "desc")
                )

            total_honeypots = len(honeypot_list)
            paginated = honeypot_list[offset : offset + page_size]
            total_pages = (total_honeypots + page_size - 1) // page_size

            return {
                "honeypots": paginated,
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

            results = (
                session.query(AccessLog.ip, func.count(AccessLog.id).label("count"))
                .group_by(AccessLog.ip)
                .all()
            )

            # Filter out local/private IPs and server IP, then sort
            filtered = [
                {"ip": row.ip, "count": row.count}
                for row in results
                if is_valid_public_ip(row.ip, server_ip)
            ]

            if sort_by == "count":
                filtered.sort(key=lambda x: x["count"], reverse=(sort_order == "desc"))
            else:  # sort by ip
                filtered.sort(key=lambda x: x["ip"], reverse=(sort_order == "desc"))

            total_ips = len(filtered)
            paginated = filtered[offset : offset + page_size]
            total_pages = (total_ips + page_size - 1) // page_size

            return {
                "ips": paginated,
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

            results = (
                session.query(AccessLog.path, func.count(AccessLog.id).label("count"))
                .group_by(AccessLog.path)
                .all()
            )

            # Create list and sort
            paths_list = [{"path": row.path, "count": row.count} for row in results]

            if sort_by == "count":
                paths_list.sort(
                    key=lambda x: x["count"], reverse=(sort_order == "desc")
                )
            else:  # sort by path
                paths_list.sort(key=lambda x: x["path"], reverse=(sort_order == "desc"))

            total_paths = len(paths_list)
            paginated = paths_list[offset : offset + page_size]
            total_pages = (total_paths + page_size - 1) // page_size

            return {
                "paths": paginated,
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

            results = (
                session.query(
                    AccessLog.user_agent, func.count(AccessLog.id).label("count")
                )
                .filter(AccessLog.user_agent.isnot(None), AccessLog.user_agent != "")
                .group_by(AccessLog.user_agent)
                .all()
            )

            # Create list and sort
            ua_list = [
                {"user_agent": row.user_agent, "count": row.count} for row in results
            ]

            if sort_by == "count":
                ua_list.sort(key=lambda x: x["count"], reverse=(sort_order == "desc"))
            else:  # sort by user_agent
                ua_list.sort(
                    key=lambda x: x["user_agent"], reverse=(sort_order == "desc")
                )

            total_uas = len(ua_list)
            paginated = ua_list[offset : offset + page_size]
            total_pages = (total_uas + page_size - 1) // page_size

            return {
                "user_agents": paginated,
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
    ) -> Dict[str, Any]:
        """
        Retrieve paginated list of detected attack types with access logs.

        Args:
            page: Page number (1-indexed)
            page_size: Number of results per page
            sort_by: Field to sort by (timestamp, ip, attack_type)
            sort_order: Sort order (asc or desc)

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

            # Get all access logs with attack detections
            query = session.query(AccessLog).join(AttackDetection)

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

            logs = query.all()

            # Convert to attack list
            attack_list = [
                {
                    "ip": log.ip,
                    "path": log.path,
                    "user_agent": log.user_agent,
                    "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                    "attack_types": [d.attack_type for d in log.attack_detections],
                }
                for log in logs
            ]

            # Sort by attack_type if needed (this must be done post-fetch since it's in a related table)
            if sort_by == "attack_type":
                attack_list.sort(
                    key=lambda x: x["attack_types"][0] if x["attack_types"] else "",
                    reverse=(sort_order == "desc"),
                )

            total_attacks = len(attack_list)
            paginated = attack_list[offset : offset + page_size]
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


# Module-level singleton instance
_db_manager = DatabaseManager()


def get_database() -> DatabaseManager:
    """Get the database manager singleton instance."""
    return _db_manager


def initialize_database(database_path: str = "data/krawl.db") -> None:
    """Initialize the database system."""
    _db_manager.initialize(database_path)
