#!/usr/bin/env python3

"""
Database singleton module for the Krawl honeypot.
Provides SQLAlchemy session management and database initialization.
"""

import collections
import os
import stat
import threading
from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import create_engine, distinct, event, func
from sqlalchemy.orm import Session, joinedload, scoped_session, sessionmaker

from database.analytics import AnalyticsRepo
from database.credentials import CredentialRepo
from database.generated_pages import GeneratedPageRepo
from database.ip_stats import IpStatsRepo
from logger import get_app_logger
from models import (
    AccessLog,
    AttackDetection,
    Base,
    CredentialAttempt,
    IpStats,
)
from sanitizer import (
    sanitize_attack_pattern,
    sanitize_credential,
    sanitize_ip,
    sanitize_path,
    sanitize_user_agent,
)

applogger = get_app_logger()

# ── Access-log write buffer (scalable mode) ──────────────────────────
# Instead of INSERT-per-request over the network, access log entries are
# buffered in memory and flushed in bulk every few seconds by a background task.
# IP stats counters are still updated synchronously (needed for ban checks).

_write_buffer: collections.deque = collections.deque()
_write_lock = threading.Lock()
_FLUSH_BATCH_SIZE = 200


def _buffer_access_log_entry(**kwargs) -> None:
    """Append an access-log entry to the in-memory write buffer."""
    kwargs["_buffered_at"] = datetime.now()
    with _write_lock:
        _write_buffer.append(kwargs)


def get_write_buffer_size() -> int:
    """Return current buffer depth (for monitoring)."""
    return len(_write_buffer)


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
            # Wire up domain sub-repositories up front so `db.<repo>` is always
            # present, even before initialize(). Each holds a back-reference to
            # the manager for session access; their methods raise the usual
            # "not initialized" error if used before initialize() (same as the
            # pre-split methods did). See database/__init__.py for rationale.
            cls._instance.credentials = CredentialRepo(cls._instance)
            cls._instance.generated_pages = GeneratedPageRepo(cls._instance)
            cls._instance.analytics = AnalyticsRepo(cls._instance)
            cls._instance.ip_stats = IpStatsRepo(cls._instance)
        return cls._instance

    def initialize(
        self,
        database_path: str = "data/krawl.db",
        mode: str = "standalone",
        postgres_config: dict = None,
    ) -> None:
        """
        Initialize the database connection and create tables.

        Args:
            database_path: Path to the SQLite database file (standalone mode)
            mode: "standalone" for SQLite, "scalable" for PostgreSQL
            postgres_config: PostgreSQL connection settings (host, port, user, password, database)
        """
        if self._initialized:
            return

        self._mode = mode

        if mode == "scalable":
            postgres_config = postgres_config or {}
            from sqlalchemy.engine import URL

            database_url = URL.create(
                drivername="postgresql+psycopg2",
                username=postgres_config.get("user", "krawl"),
                password=postgres_config.get("password", ""),
                host=postgres_config.get("host", "localhost"),
                port=int(postgres_config.get("port", 5432)),
                database=postgres_config.get("database", "krawl"),
            )
            self._engine = create_engine(
                database_url,
                pool_size=10,
                max_overflow=20,
                pool_pre_ping=True,
                pool_recycle=1800,
                echo=False,
            )
            applogger.info(
                f"Using PostgreSQL at {postgres_config['host']}:{postgres_config['port']}"
                f"/{postgres_config['database']}"
            )
        else:
            # Standalone: SQLite
            data_dir = os.path.dirname(database_path)
            if data_dir and not os.path.exists(data_dir):
                os.makedirs(data_dir, exist_ok=True)

            database_url = f"sqlite:///{database_path}"
            self._engine = create_engine(
                database_url,
                connect_args={"check_same_thread": False},
                echo=False,
            )

            # Register SQLite PRAGMAs on this specific engine instance
            @event.listens_for(self._engine, "connect")
            def set_sqlite_pragma(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA busy_timeout=30000")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA wal_autocheckpoint=5000")
                cursor.close()

        # Create session factory with scoped_session for thread safety
        session_factory = sessionmaker(bind=self._engine)
        self._Session = scoped_session(session_factory)

        # Create all tables
        Base.metadata.create_all(self._engine)

        # Run migrations (dialect-agnostic via SQLAlchemy Inspector)
        if mode == "standalone":
            self._run_migrations(database_path)

        from migrations.runner import run_migrations

        run_migrations(self._engine)

        # Set restrictive file permissions for SQLite (owner read/write only)
        if mode == "standalone" and os.path.exists(database_path):
            try:
                os.chmod(database_path, stat.S_IRUSR | stat.S_IWUSR)  # 600
            except OSError:
                pass

        self._initialized = True

    def _run_migrations(self, database_path: str) -> None:
        """
        Run legacy SQLite-specific auto-migrations for backward compatibility.
        Only runs in standalone mode. Adds missing columns from older versions.

        Args:
            database_path: Path to the SQLite database file
        """
        if getattr(self, "_mode", "standalone") != "standalone":
            return

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
        attack_types: list[str] | None = None,
        matched_patterns: dict[str, str] | None = None,
        raw_request: str | None = None,
        increment_page_visit: bool = False,
        max_pages_limit: int = 0,
    ) -> int:
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
            increment_page_visit: Also bump the page visit counter in the same tx
            max_pages_limit: Ban threshold (used with increment_page_visit)

        Returns:
            The page visit count (0 when increment_page_visit is False)
        """
        from config import get_config

        config = get_config()
        persist_suspicious_only = config.database_persist_suspicious_only
        scalable = config.mode == "scalable"

        session = self.session
        try:
            # In scalable mode, buffer access log writes and flush in bulk later.
            # In standalone mode (local SQLite), write immediately.
            if scalable:
                if not persist_suspicious_only or is_suspicious:
                    _buffer_access_log_entry(
                        ip=ip,
                        path=path,
                        user_agent=user_agent,
                        method=method,
                        is_suspicious=is_suspicious,
                        is_honeypot_trigger=is_honeypot_trigger,
                        attack_types=attack_types,
                        matched_patterns=matched_patterns,
                        raw_request=raw_request,
                    )
            else:
                if not persist_suspicious_only or is_suspicious:
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
                    session.flush()

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

            # Always update IP stats counters (+ optional page visit increment)
            page_visit_count, was_new_ip, was_first_honeypot = self._update_ip_stats(
                session,
                ip,
                is_suspicious,
                is_honeypot_trigger=is_honeypot_trigger,
                increment_page_visit=increment_page_visit,
                max_pages_limit=max_pages_limit,
            )

            session.commit()

            # Update event-driven metric counters after the DB commit. A crash
            # between commit and here causes at most bounded drift, corrected by
            # the next startup reseed — acceptable per the design.
            try:
                import metrics_counters as mc

                if self._is_counted_ip(ip):
                    mc.increment("total_accesses")
                    if is_suspicious:
                        mc.increment("suspicious_accesses")
                    if was_new_ip:
                        mc.increment("unique_ips")
                    if is_honeypot_trigger:
                        mc.increment("honeypot_triggered")
                    if was_first_honeypot:
                        mc.increment("honeypot_ips")
                    if mc.add_to_set("paths", sanitize_path(path)):
                        mc.increment("unique_paths")
                    if attack_types:
                        for attack_type in attack_types:
                            mc.increment("attack_detections", attack_type[:50])
            except Exception as e:
                applogger.error(f"Metric counter update failed: {e}")

            return page_visit_count

        except Exception as e:
            session.rollback()
            applogger.critical(f"Database error persisting access: {e}")
            return 0
        finally:
            self.close_session()

    def flush_access_log_buffer(self) -> int:
        """
        Bulk-insert buffered access log entries into the database.

        Called periodically by a background task in scalable mode.
        Returns the number of entries flushed.
        """
        entries = []
        with _write_lock:
            for _ in range(min(len(_write_buffer), _FLUSH_BATCH_SIZE)):
                entries.append(_write_buffer.popleft())

        if not entries:
            return 0

        session = self.session
        try:
            for entry in entries:
                ts = entry.pop("_buffered_at", datetime.now())
                attack_types = entry.pop("attack_types", None)
                matched_patterns = entry.pop("matched_patterns", None) or {}

                access_log = AccessLog(
                    ip=sanitize_ip(entry["ip"]),
                    path=sanitize_path(entry["path"]),
                    user_agent=sanitize_user_agent(entry.get("user_agent", "")),
                    method=(entry.get("method", "GET"))[:10],
                    is_suspicious=entry.get("is_suspicious", False),
                    is_honeypot_trigger=entry.get("is_honeypot_trigger", False),
                    timestamp=ts,
                    raw_request=entry.get("raw_request"),
                )
                session.add(access_log)

                if attack_types:
                    session.flush()
                    for attack_type in attack_types:
                        detection = AttackDetection(
                            access_log_id=access_log.id,
                            attack_type=attack_type[:50],
                            matched_pattern=sanitize_attack_pattern(
                                matched_patterns.get(attack_type, "")
                            ),
                        )
                        session.add(detection)

            session.commit()
            return len(entries)

        except Exception as e:
            session.rollback()
            applogger.error(
                f"Error flushing access log buffer ({len(entries)} entries): {e}"
            )
            # Re-queue failed entries so they aren't lost
            with _write_lock:
                _write_buffer.extendleft(reversed(entries))
            return 0
        finally:
            self.close_session()

    def persist_credential(
        self,
        ip: str,
        path: str,
        username: str | None = None,
        password: str | None = None,
    ) -> int | None:
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
            try:
                import metrics_counters as mc

                mc.increment("credentials_captured")
            except Exception as e:
                applogger.error(f"Metric counter update failed: {e}")
            return credential.id

        except Exception as e:
            session.rollback()
            applogger.critical(f"Database error persisting credential: {e}")
            return None
        finally:
            self.close_session()

    def _update_ip_stats(
        self,
        session: Session,
        ip: str,
        is_suspicious: bool = False,
        is_honeypot_trigger: bool = False,
        increment_page_visit: bool = False,
        max_pages_limit: int = 0,
    ):
        """
        Update IP statistics (upsert pattern).

        Args:
            session: Active database session
            ip: IP address to update
            is_suspicious: Whether the request was flagged as suspicious
            increment_page_visit: Also increment page visit counter
            max_pages_limit: Ban threshold (only used when increment_page_visit=True)

        Returns:
            The page visit count (0 if increment_page_visit is False)
        """
        sanitized_ip = sanitize_ip(ip)
        now = datetime.now()

        ip_stats = session.query(IpStats).filter(IpStats.ip == sanitized_ip).first()

        was_new_ip = False
        was_first_honeypot = False

        if ip_stats:
            ip_stats.total_requests += 1
            ip_stats.last_seen = now
            if is_suspicious:
                ip_stats.need_reevaluation = True
        else:
            was_new_ip = True
            ip_stats = IpStats(
                ip=sanitized_ip,
                total_requests=1,
                first_seen=now,
                last_seen=now,
                need_reevaluation=is_suspicious,
                page_visit_count=0,
            )
            session.add(ip_stats)

        if is_honeypot_trigger and not ip_stats.has_triggered_honeypot:
            ip_stats.has_triggered_honeypot = True
            was_first_honeypot = True

        page_visit_count = 0
        if increment_page_visit:
            ip_stats.page_visit_count = (ip_stats.page_visit_count or 0) + 1
            page_visit_count = ip_stats.page_visit_count

            if max_pages_limit > 0 and page_visit_count >= max_pages_limit:
                ip_stats.total_violations = (ip_stats.total_violations or 0) + 1
                ip_stats.ban_multiplier = 2 ** (ip_stats.total_violations - 1)
                ip_stats.ban_timestamp = now
                # Invalidate cached ban info so the new ban is enforced immediately
                from dashboard_cache import delete_cached_short

                delete_cached_short(f"ban:{sanitized_ip}")

        return page_visit_count, was_new_ip, was_first_honeypot

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

            # Invalidate cached ban info so the new ban is enforced immediately
            if ip_stats.ban_timestamp is not None:
                from dashboard_cache import delete_cached_short

                delete_cached_short(f"ban:{sanitized_ip}")

            return ip_stats.page_visit_count

        except Exception as e:
            session.rollback()
            applogger.error(f"Error incrementing page visit for {ip}: {e}")
            return 0
        finally:
            self.close_session()





        # Note: clients_total is NOT maintained as a +new/-old delta counter.
        # It is current-state and recomputed live from count_category at scrape
        # time (see metrics.KrawlMetricsCollector), which is cheap (indexed) and
        # avoids the unbounded drift a delta accrues under retention deletes.







    def get_access_logs_paginated(
        self,
        page: int = 1,
        page_size: int = 25,
        ip_filter: str | None = None,
        suspicious_only: bool = False,
        since_minutes: int | None = None,
        sort_order: str = "desc",
    ) -> dict[str, Any]:
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
            query = (
                session.query(AccessLog)
                .options(joinedload(AccessLog.attack_detections))
                .order_by(order)
            )

            if ip_filter:
                query = query.filter(AccessLog.ip == sanitize_ip(ip_filter))
            if suspicious_only:
                query = query.filter(AccessLog.is_suspicious)
            if since_minutes is not None:
                cutoff_time = datetime.now() - timedelta(minutes=since_minutes)
                query = query.filter(AccessLog.timestamp >= cutoff_time)

            logs = query.offset(offset).limit(page_size).all()

            # Count query with same filters
            count_query = session.query(func.count(AccessLog.id))
            if ip_filter:
                count_query = count_query.filter(AccessLog.ip == sanitize_ip(ip_filter))
            if suspicious_only:
                count_query = count_query.filter(AccessLog.is_suspicious)
            if since_minutes is not None:
                count_query = count_query.filter(AccessLog.timestamp >= cutoff_time)
            total_access_logs = count_query.scalar()
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
        ip_filter: str | None = None,
        suspicious_only: bool = False,
        since_minutes: int | None = None,
    ) -> list[dict[str, Any]]:
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
            query = (
                session.query(AccessLog)
                .options(joinedload(AccessLog.attack_detections))
                .order_by(AccessLog.timestamp.desc())
            )

            if ip_filter:
                query = query.filter(AccessLog.ip == sanitize_ip(ip_filter))
            if suspicious_only:
                query = query.filter(AccessLog.is_suspicious)
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






    def _public_ip_filter(self, query, ip_column, server_ip: str | None = None):
        """Apply SQL-level filter to exclude the server's own IP."""
        if server_ip:
            query = query.filter(ip_column != server_ip)
        return query

    def _is_counted_ip(self, ip: str) -> bool:
        """Whether an IP contributes to aggregate counters.

        Mirrors _public_ip_filter semantics (only the server's own IP is
        excluded) so event-driven counters match get_dashboard_counts.
        """
        from config import get_config

        server_ip = get_config().get_server_ip()
        return bool(ip) and ip != server_ip

    def get_dashboard_counts(self) -> dict[str, int]:
        """
        Return aggregate dashboard counts from the live cache counters.

        Counters are seeded at startup (from metrics_summary or a one-time
        recompute) and maintained event-driven on the write path, so this
        avoids the full access_logs scans that _compute_dashboard_counts_sql
        performs.
        """
        import metrics_counters as mc

        return {
            "total_accesses": mc.get("total_accesses"),
            "unique_ips": mc.get("unique_ips"),
            "unique_paths": mc.get("unique_paths"),
            "suspicious_accesses": mc.get("suspicious_accesses"),
            "honeypot_triggered": mc.get("honeypot_triggered"),
            "honeypot_ips": mc.get("honeypot_ips"),
            # clients_total is current-state (recomputed live), not a cumulative
            # counter — read it straight from the indexed category count.
            "unique_attackers": self.ip_stats.count_category("attacker"),
        }

    def _compute_dashboard_counts_sql(self) -> dict[str, int]:
        """
        Get aggregate statistics for the dashboard (excludes local/private IPs and server IP).

        Derives total_accesses and unique_ips from ip_stats (one row per IP)
        to avoid full table scans on the large access_logs table.
        Boolean-indexed columns are queried individually so the database can
        use index range scans instead of a single full-table aggregation.

        Returns:
            Dictionary with total_accesses, unique_ips, unique_paths,
            suspicious_accesses, honeypot_triggered, honeypot_ips
        """
        session = self.session
        try:
            from config import get_config

            config = get_config()
            server_ip = config.get_server_ip()

            # --- Fast path: derive from ip_stats (tiny table, one row per IP) ---
            ip_base = session.query(
                func.sum(IpStats.total_requests).label("total_accesses"),
                func.count(IpStats.ip).label("unique_ips"),
            )
            ip_base = self._public_ip_filter(ip_base, IpStats.ip, server_ip)
            ip_row = ip_base.one()

            unique_attackers = session.query(func.count(IpStats.ip)).filter(
                IpStats.category == "attacker"
            )
            unique_attackers = self._public_ip_filter(
                unique_attackers, IpStats.ip, server_ip
            )
            unique_attackers = unique_attackers.scalar() or 0

            # --- Single scan on access_logs using conditional aggregation ---
            from sqlalchemy import case

            logs_q = session.query(
                func.count(case((AccessLog.is_suspicious, AccessLog.id))).label(
                    "suspicious_accesses"
                ),
                func.count(case((AccessLog.is_honeypot_trigger, AccessLog.id))).label(
                    "honeypot_triggered"
                ),
                func.count(
                    distinct(case((AccessLog.is_honeypot_trigger, AccessLog.ip)))
                ).label("honeypot_ips"),
                func.count(distinct(AccessLog.path)).label("unique_paths"),
            )
            logs_q = self._public_ip_filter(logs_q, AccessLog.ip, server_ip)
            logs_row = logs_q.one()

            suspicious_accesses = logs_row.suspicious_accesses or 0
            honeypot_triggered = logs_row.honeypot_triggered or 0
            honeypot_ips = logs_row.honeypot_ips or 0
            unique_paths = logs_row.unique_paths or 0

            return {
                "total_accesses": int(ip_row.total_accesses or 0),
                "unique_ips": int(ip_row.unique_ips or 0),
                "unique_paths": int(unique_paths),
                "suspicious_accesses": int(suspicious_accesses),
                "honeypot_triggered": int(honeypot_triggered),
                "honeypot_ips": int(honeypot_ips),
                "unique_attackers": int(unique_attackers),
            }
        finally:
            self.close_session()





    def get_distinct_paths(self) -> list[str]:
        """Return all distinct request paths (used to seed the unique_paths set)."""
        session = self.session
        try:
            from config import get_config

            server_ip = get_config().get_server_ip()
            query = session.query(distinct(AccessLog.path))
            query = self._public_ip_filter(query, AccessLog.ip, server_ip)
            return [row[0] for row in query.all() if row[0] is not None]
        except Exception as e:
            applogger.error(f"Error reading distinct paths: {e}")
            return []
        finally:
            self.close_session()




    def get_recent_suspicious(self, limit: int = 20) -> list[dict[str, Any]]:
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
                .filter(AccessLog.is_suspicious)
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

    def get_honeypot_triggered_ips(self) -> list[tuple]:
        """
        Get IPs that triggered honeypot paths with the paths they accessed
        (excludes local/private IPs and server IP).

        Returns:
            List of (ip, [paths]) tuples
        """
        session = self.session
        try:
            # Get distinct IP/path combos for honeypot triggers
            results = (
                session.query(AccessLog.ip, AccessLog.path)
                .filter(AccessLog.is_honeypot_trigger)
                .group_by(AccessLog.ip, AccessLog.path)
                .all()
            )

            # Group paths by IP
            ip_paths: dict[str, list[str]] = {}
            for row in results:
                if row.ip not in ip_paths:
                    ip_paths[row.ip] = []
                ip_paths[row.ip].append(row.path)

            return [(ip, paths) for ip, paths in ip_paths.items()]
        finally:
            self.close_session()

    def get_recent_attacks(self, limit: int = 20) -> list[dict[str, Any]]:
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
                .options(joinedload(AccessLog.attack_detections))
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
    ) -> dict[str, Any]:
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
                AccessLog.is_honeypot_trigger
            )
            base_query = self._public_ip_filter(base_query, AccessLog.ip, server_ip)
            base_query = base_query.group_by(AccessLog.ip)

            # Get total count of distinct honeypot IPs
            count_hp = session.query(func.count(distinct(AccessLog.ip))).filter(
                AccessLog.is_honeypot_trigger
            )
            count_hp = self._public_ip_filter(count_hp, AccessLog.ip, server_ip)
            total_honeypots = count_hp.scalar() or 0

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
                        AccessLog.is_honeypot_trigger,
                        AccessLog.ip.in_(paginated_ips),
                    )
                    .group_by(AccessLog.ip, AccessLog.path)
                    .all()
                )
                ip_paths: dict[str, list[str]] = {}
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





    def get_raw_request_by_id(self, log_id: int) -> str | None:
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




    # ── Ban Override Management ──────────────────────────────────────────




    # ── IP Tracking ──────────────────────────────────────────────────







# Module-level singleton instance
_db_manager = DatabaseManager()


def get_database() -> DatabaseManager:
    """Get the database manager singleton instance."""
    return _db_manager


def initialize_database(
    database_path: str = "data/krawl.db",
    mode: str = "standalone",
    postgres_config: dict = None,
) -> None:
    """Initialize the database system."""
    _db_manager.initialize(database_path, mode=mode, postgres_config=postgres_config)
