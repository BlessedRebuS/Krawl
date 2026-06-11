#!/usr/bin/env python3

"""
Database singleton module for the Krawl honeypot.
Provides SQLAlchemy session management and database initialization.
"""

import collections
import os
import stat
import threading
from datetime import datetime
from typing import Optional

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, scoped_session, sessionmaker

from database.access_logs import AccessLogRepo
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
            cls._instance.access_logs = AccessLogRepo(cls._instance)
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
