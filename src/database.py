#!/usr/bin/env python3

"""
Database singleton module for the Krawl honeypot.
Provides SQLAlchemy session management and database initialization.
"""

import os
import stat
from datetime import datetime
from typing import Optional, List, Dict, Any
from zoneinfo import ZoneInfo

from sqlalchemy import create_engine, func, distinct, case
from sqlalchemy.orm import sessionmaker, scoped_session, Session

from models import Base, AccessLog, CredentialAttempt, AttackDetection, IpStats, CategoryHistory
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
            echo=False  # Set to True for SQL debugging
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
            raise RuntimeError("DatabaseManager not initialized. Call initialize() first.")
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
        matched_patterns: Optional[Dict[str, str]] = None
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
                timestamp=datetime.now(tz=ZoneInfo('UTC'))
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
                        )
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
        password: Optional[str] = None
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
                timestamp=datetime.now(tz=ZoneInfo('UTC'))
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
        now = datetime.now(tz=ZoneInfo('UTC'))

        ip_stats = session.query(IpStats).filter(IpStats.ip == sanitized_ip).first()

        if ip_stats:
            ip_stats.total_requests += 1
            ip_stats.last_seen = now
        else:
            ip_stats = IpStats(
                ip=sanitized_ip,
                total_requests=1,
                first_seen=now,
                last_seen=now
            )
            session.add(ip_stats)

    def  update_ip_stats_analysis(self, ip: str, analyzed_metrics: Dict[str, object], category: str, category_scores: Dict[str, int], last_analysis: datetime) -> None:
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
        applogger.debug(f"Analyzed metrics {analyzed_metrics}, category {category}, category scores {category_scores}, last analysis {last_analysis}")
        applogger.info(f"IP: {ip} category has been updated to {category}")

        session = self.session
        sanitized_ip = sanitize_ip(ip)
        ip_stats = session.query(IpStats).filter(IpStats.ip == sanitized_ip).first()

        # Check if category has changed and record it
        old_category = ip_stats.category
        if old_category != category:
            self._record_category_change(sanitized_ip, old_category, category, last_analysis)

        ip_stats.analyzed_metrics = analyzed_metrics
        ip_stats.category = category
        ip_stats.category_scores = category_scores
        ip_stats.last_analysis = last_analysis
        
        try:
            session.commit()
        except Exception as e:
            session.rollback()
            print(f"Error updating IP stats analysis: {e}")

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
            self._record_category_change(sanitized_ip, old_category, category, datetime.now(tz=ZoneInfo('UTC')))

        ip_stats.category = category
        ip_stats.manual_category = True
        
        try:
            session.commit()
        except Exception as e:
            session.rollback()
            print(f"Error updating manual category: {e}")

    def _record_category_change(self, ip: str, old_category: Optional[str], new_category: str, timestamp: datetime) -> None:
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
                timestamp=timestamp
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
            history = session.query(CategoryHistory).filter(
                CategoryHistory.ip == sanitized_ip
            ).order_by(CategoryHistory.timestamp.asc()).all()

            return [
                {
                    'old_category': h.old_category,
                    'new_category': h.new_category,
                    'timestamp': h.timestamp.isoformat() + '+00:00'
                }
                for h in history
            ]
        finally:
            self.close_session()

    def update_ip_rep_infos(self, ip: str, country_code: str, asn: str, asn_org: str, list_on: Dict[str,str]) -> None:
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
        
        sanitized_ip = sanitize_ip(ip)
        ip_stats = session.query(IpStats).filter(IpStats.ip == sanitized_ip).first()

        ip_stats.country_code = country_code
        ip_stats.asn = asn
        ip_stats.asn_org = asn_org
        ip_stats.list_on = list_on


    def get_access_logs(
        self,
        limit: int = 100,
        offset: int = 0,
        ip_filter: Optional[str] = None,
        suspicious_only: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Retrieve access logs with optional filtering.

        Args:
            limit: Maximum number of records to return
            offset: Number of records to skip
            ip_filter: Filter by IP address
            suspicious_only: Only return suspicious requests

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

            logs = query.offset(offset).limit(limit).all()

            return [
                {
                    'id': log.id,
                    'ip': log.ip,
                    'path': log.path,
                    'user_agent': log.user_agent,
                    'method': log.method,
                    'is_suspicious': log.is_suspicious,
                    'is_honeypot_trigger': log.is_honeypot_trigger,
                    'timestamp': log.timestamp.isoformat() + '+00:00',
                    'attack_types': [d.attack_type for d in log.attack_detections]
                }
                for log in logs
            ]
        finally:
            self.close_session()

    # def persist_ip(
    #     self,
    #     ip: str
    # ) -> Optional[int]:
    #     """
    #     Persist an ip entry to the database.

    #     Args:
    #         ip: Client IP address

    #     Returns:
    #         The ID of the created IpLog record, or None on error
    #     """
    #     session = self.session
    #     try:
    #         # Create access log with sanitized fields
    #         ip_log = AccessLog(
    #             ip=sanitize_ip(ip),
    #             manual_category = False
    #         )
    #         session.add(access_log)
    #         session.flush()  # Get the ID before committing

    #         # Add attack detections if any
    #         if attack_types:
    #             matched_patterns = matched_patterns or {}
    #             for attack_type in attack_types:
    #                 detection = AttackDetection(
    #                     access_log_id=access_log.id,
    #                     attack_type=attack_type[:50],
    #                     matched_pattern=sanitize_attack_pattern(
    #                         matched_patterns.get(attack_type, "")
    #                     )
    #                 )
    #                 session.add(detection)

    #         # Update IP stats
    #         self._update_ip_stats(session, ip)

    #         session.commit()
    #         return access_log.id

    #     except Exception as e:
    #         session.rollback()
    #         # Log error but don't crash - database persistence is secondary to honeypot function
    #         print(f"Database error persisting access: {e}")
    #         return None
    #     finally:
    #         self.close_session()    

    def get_credential_attempts(
        self,
        limit: int = 100,
        offset: int = 0,
        ip_filter: Optional[str] = None
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
                    'id': attempt.id,
                    'ip': attempt.ip,
                    'path': attempt.path,
                    'username': attempt.username,
                    'password': attempt.password,
                    'timestamp': attempt.timestamp.isoformat() + '+00:00'
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
            stats = session.query(IpStats).order_by(
                IpStats.total_requests.desc()
            ).limit(limit).all()

            return [
                {
                    'ip': s.ip,
                    'total_requests': s.total_requests,
                    'first_seen': s.first_seen.isoformat() + '+00:00',
                    'last_seen': s.last_seen.isoformat() + '+00:00',
                    'country_code': s.country_code,
                    'city': s.city,
                    'asn': s.asn,
                    'asn_org': s.asn_org,
                    'reputation_score': s.reputation_score,
                    'reputation_source': s.reputation_source,
                    'analyzed_metrics': s.analyzed_metrics,
                    'category': s.category,
                    'manual_category': s.manual_category,
                    'last_analysis': s.last_analysis
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
                'ip': stat.ip,
                'total_requests': stat.total_requests,
                'first_seen': stat.first_seen.isoformat() + '+00:00' if stat.first_seen else None,
                'last_seen': stat.last_seen.isoformat() + '+00:00' if stat.last_seen else None,
                'country_code': stat.country_code,
                'city': stat.city,
                'asn': stat.asn,
                'asn_org': stat.asn_org,
                'list_on': stat.list_on or {},
                'reputation_score': stat.reputation_score,
                'reputation_source': stat.reputation_source,
                'analyzed_metrics': stat.analyzed_metrics or {},
                'category': stat.category,
                'category_scores': stat.category_scores or {},
                'manual_category': stat.manual_category,
                'last_analysis': stat.last_analysis.isoformat() + '+00:00' if stat.last_analysis else None,
                'category_history': category_history
            }
        finally:
            self.close_session()

    def get_dashboard_counts(self) -> Dict[str, int]:
        """
        Get aggregate statistics for the dashboard.

        Returns:
            Dictionary with total_accesses, unique_ips, unique_paths,
            suspicious_accesses, honeypot_triggered, honeypot_ips
        """
        session = self.session
        try:
            # Get main aggregate counts in one query
            result = session.query(
                func.count(AccessLog.id).label('total_accesses'),
                func.count(distinct(AccessLog.ip)).label('unique_ips'),
                func.count(distinct(AccessLog.path)).label('unique_paths'),
                func.sum(case((AccessLog.is_suspicious == True, 1), else_=0)).label('suspicious_accesses'),
                func.sum(case((AccessLog.is_honeypot_trigger == True, 1), else_=0)).label('honeypot_triggered')
            ).first()

            # Get unique IPs that triggered honeypots
            honeypot_ips = session.query(
                func.count(distinct(AccessLog.ip))
            ).filter(AccessLog.is_honeypot_trigger == True).scalar() or 0

            return {
                'total_accesses': result.total_accesses or 0,
                'unique_ips': result.unique_ips or 0,
                'unique_paths': result.unique_paths or 0,
                'suspicious_accesses': int(result.suspicious_accesses or 0),
                'honeypot_triggered': int(result.honeypot_triggered or 0),
                'honeypot_ips': honeypot_ips
            }
        finally:
            self.close_session()

    def get_top_ips(self, limit: int = 10) -> List[tuple]:
        """
        Get top IP addresses by access count.

        Args:
            limit: Maximum number of results

        Returns:
            List of (ip, count) tuples ordered by count descending
        """
        session = self.session
        try:
            results = session.query(
                AccessLog.ip,
                func.count(AccessLog.id).label('count')
            ).group_by(AccessLog.ip).order_by(
                func.count(AccessLog.id).desc()
            ).limit(limit).all()

            return [(row.ip, row.count) for row in results]
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
            results = session.query(
                AccessLog.path,
                func.count(AccessLog.id).label('count')
            ).group_by(AccessLog.path).order_by(
                func.count(AccessLog.id).desc()
            ).limit(limit).all()

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
            results = session.query(
                AccessLog.user_agent,
                func.count(AccessLog.id).label('count')
            ).filter(
                AccessLog.user_agent.isnot(None),
                AccessLog.user_agent != ''
            ).group_by(AccessLog.user_agent).order_by(
                func.count(AccessLog.id).desc()
            ).limit(limit).all()

            return [(row.user_agent, row.count) for row in results]
        finally:
            self.close_session()

    def get_recent_suspicious(self, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Get recent suspicious access attempts.

        Args:
            limit: Maximum number of results

        Returns:
            List of access log dictionaries with is_suspicious=True
        """
        session = self.session
        try:
            logs = session.query(AccessLog).filter(
                AccessLog.is_suspicious == True
            ).order_by(AccessLog.timestamp.desc()).limit(limit).all()

            return [
                {
                    'ip': log.ip,
                    'path': log.path,
                    'user_agent': log.user_agent,
                    'timestamp': log.timestamp.isoformat() + '+00:00'
                }
                for log in logs
            ]
        finally:
            self.close_session()

    def get_honeypot_triggered_ips(self) -> List[tuple]:
        """
        Get IPs that triggered honeypot paths with the paths they accessed.

        Returns:
            List of (ip, [paths]) tuples
        """
        session = self.session
        try:
            # Get all honeypot triggers grouped by IP
            results = session.query(
                AccessLog.ip,
                AccessLog.path
            ).filter(
                AccessLog.is_honeypot_trigger == True
            ).all()

            # Group paths by IP
            ip_paths: Dict[str, List[str]] = {}
            for row in results:
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
            logs = session.query(AccessLog).join(
                AttackDetection
            ).order_by(AccessLog.timestamp.desc()).limit(limit).all()

            return [
                {
                    'ip': log.ip,
                    'path': log.path,
                    'user_agent': log.user_agent,
                    'timestamp': log.timestamp.isoformat() + '+00:00',
                    'attack_types': [d.attack_type for d in log.attack_detections]
                }
                for log in logs
            ]
        finally:
            self.close_session()

    # def get_ip_logs(
    #     self,
    #     limit: int = 100,
    #     offset: int = 0,
    #     ip_filter: Optional[str] = None
    # ) -> List[Dict[str, Any]]:
    #     """
    #     Retrieve ip logs with optional filtering.

    #     Args:
    #         limit: Maximum number of records to return
    #         offset: Number of records to skip
    #         ip_filter: Filter by IP address

    #     Returns:
    #         List of ip log dictionaries
    #     """
    #     session = self.session
    #     try:
    #         query = session.query(IpLog).order_by(IpLog.last_access.desc())

    #         if ip_filter:
    #             query = query.filter(IpLog.ip == sanitize_ip(ip_filter))

    #         logs = query.offset(offset).limit(limit).all()

    #         return [
    #             {
    #                 'id': log.id,
    #                 'ip': log.ip,
    #                 'stats': log.stats,
    #                 'category': log.category,
    #                 'manual_category': log.manual_category,
    #                 'last_evaluation': log.last_evaluation,
    #                 'last_access': log.last_access
    #             }
    #             for log in logs
    #         ]
    #     finally:
    #         self.close_session()


# Module-level singleton instance
_db_manager = DatabaseManager()


def get_database() -> DatabaseManager:
    """Get the database manager singleton instance."""
    return _db_manager


def initialize_database(database_path: str = "data/krawl.db") -> None:
    """Initialize the database system."""
    _db_manager.initialize(database_path)
