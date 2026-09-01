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

from sqlalchemy import create_engine, event, insert
from sqlalchemy.orm import Session, scoped_session, sessionmaker

from database.access_logs import AccessLogRepo
from database.analytics import AnalyticsRepo
from database.credentials import CredentialRepo
from database.generated_pages import GeneratedPageRepo
from database.ip_stats import IpStatsRepo
from ip_utils import defer_persist
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

# Cap the exponential ban backoff so ban_multiplier never overflows the
# Integer (int4) column. With the default 600s base ban, 2**10 = 1024 caps the
# effective ban at roughly a week — repeat offenders saturate here instead of
# growing unbounded and crashing the persist with "integer out of range".
MAX_BAN_EXPONENT = 10


def _ban_multiplier_for(total_violations: int) -> int:
    """Exponential backoff multiplier, clamped to avoid int4 overflow."""
    exponent = min(max(total_violations - 1, 0), MAX_BAN_EXPONENT)
    return 2**exponent


# ── Access-log write buffer (scalable mode) ──────────────────────────
# Instead of INSERT-per-request over the network, access log entries are
# buffered in memory and flushed in bulk every few seconds by a background task.
# IP stats counters are still updated synchronously (needed for ban checks).

# Statement size, not a per-flush ceiling: the flush loops until drained.
_FLUSH_BATCH_SIZE = 200

# Two ceilings, because a row count is not a memory bound. Entries carry
# `raw_request`, capped at MAX_RAW_REQUEST (16 KiB), so 50k rows is anywhere
# between ~60 MiB and ~800 MiB depending on what the traffic looks like — and
# an attack flood is exactly the traffic that fills the buffer with large
# entries. The byte budget is what actually holds RSS down; the row cap stays
# as a cheap second guard.
_MAX_BUFFER_ROWS = 50_000
_MAX_BUFFER_BYTES = 64 * 1024 * 1024

_write_buffer: collections.deque = collections.deque(maxlen=_MAX_BUFFER_ROWS)
_write_lock = threading.Lock()
_dropped_rows = 0
_buffer_bytes = 0


def _entry_bytes(entry: dict) -> int:
    """Approximate heap cost of a buffered entry.

    Only the string payloads are worth counting — they are the part that
    varies by three orders of magnitude. The rest is a fixed dict overhead,
    approximated by the constant.
    """
    raw = entry.get("raw_request") or ""
    return (
        len(raw)
        + len(entry.get("path") or "")
        + len(entry.get("user_agent") or "")
        + len(entry.get("ip") or "")
        + 512
    )


def _buffer_access_log_entry(**kwargs) -> None:
    """Append an access-log entry to the in-memory write buffer.

    Evicts oldest-first when either ceiling is hit, and counts the losses, so
    a flush task that falls behind degrades into dropped rows rather than an
    OOM kill.
    """
    global _dropped_rows, _buffer_bytes
    kwargs["_buffered_at"] = datetime.now()
    size = _entry_bytes(kwargs)
    with _write_lock:
        if len(_write_buffer) == _MAX_BUFFER_ROWS:
            # maxlen evicts from the left on append; account for it ourselves.
            _buffer_bytes -= _entry_bytes(_write_buffer[0])
            _dropped_rows += 1
        _write_buffer.append(kwargs)
        _buffer_bytes += size

        while _buffer_bytes > _MAX_BUFFER_BYTES and len(_write_buffer) > 1:
            _buffer_bytes -= _entry_bytes(_write_buffer.popleft())
            _dropped_rows += 1


def get_write_buffer_size() -> int:
    """Return current buffer depth (for monitoring)."""
    return len(_write_buffer)


def get_write_buffer_bytes() -> int:
    """Approximate bytes held by the write buffer (for monitoring)."""
    return _buffer_bytes


def get_dropped_rows() -> int:
    """Access-log rows dropped because the buffer was full (for monitoring)."""
    return _dropped_rows


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
        from migrations.runner import run_migrations

        run_migrations(self._engine)

        # Collect planner statistics if this database has never had any. Runs
        # after the migrations so the autovacuum thresholds they set are in
        # place first; a no-op on every boot but the first.
        from database.maintenance import bootstrap_analyze

        bootstrap_analyze(self._engine)

        # Set restrictive file permissions for SQLite (owner read/write only)
        if mode == "standalone" and os.path.exists(database_path):
            try:
                os.chmod(database_path, stat.S_IRUSR | stat.S_IWUSR)  # 600
            except OSError:
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

    @property
    def engine(self):
        """The SQLAlchemy Engine, for statements that cannot run in a session.

        ANALYZE and friends need connection-level control (AUTOCOMMIT), which a
        thread-local ORM session does not give.
        """
        if not self._initialized:
            raise RuntimeError(
                "DatabaseManager not initialized. Call initialize() first."
            )
        return self._engine

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

    def _pop_batch(self, n: int) -> list[dict]:
        """Remove up to n entries from the front of the write buffer."""
        global _buffer_bytes
        with _write_lock:
            batch = [_write_buffer.popleft() for _ in range(min(len(_write_buffer), n))]
            _buffer_bytes -= sum(_entry_bytes(e) for e in batch)
            return batch

    def flush_access_log_buffer(self, max_rows: int = 50_000) -> int:
        """
        Bulk-insert buffered access log entries into the database.

        Drains in _FLUSH_BATCH_SIZE statements until empty, so the flush rate
        follows arrival rate. max_rows caps the work one run may do.

        Returns the number of entries flushed.
        """
        total = 0
        while total < max_rows:
            entries = self._pop_batch(_FLUSH_BATCH_SIZE)
            if not entries:
                break
            inserted = self._insert_access_log_batch(entries)
            if inserted == 0:
                break  # batch failed and was re-queued; stop to avoid spinning
            total += inserted
        return total

    def _insert_access_log_batch(self, entries: list[dict]) -> int:
        """Insert one batch of buffered entries: two statements, not two per row."""
        session = self.session
        try:
            logs, attacks_per_entry = [], []
            for entry in entries:
                ts = entry.pop("_buffered_at", datetime.now())
                attacks_per_entry.append(
                    (
                        entry.pop("attack_types", None),
                        entry.pop("matched_patterns", None) or {},
                    )
                )
                logs.append(
                    {
                        "ip": sanitize_ip(entry["ip"]),
                        "path": sanitize_path(entry["path"]),
                        "user_agent": sanitize_user_agent(entry.get("user_agent", "")),
                        "method": (entry.get("method", "GET"))[:10],
                        "is_suspicious": entry.get("is_suspicious", False),
                        "is_honeypot_trigger": entry.get("is_honeypot_trigger", False),
                        "timestamp": ts,
                        "raw_request": entry.get("raw_request"),
                    }
                )

            # sort_by_parameter_order: without it RETURNING order is undefined
            # and detections attach to the wrong rows.
            log_ids = session.scalars(
                insert(AccessLog).returning(AccessLog.id, sort_by_parameter_order=True),
                logs,
            ).all()

            detections = [
                {
                    "access_log_id": log_id,
                    "attack_type": attack_type[:50],
                    "matched_pattern": sanitize_attack_pattern(
                        patterns.get(attack_type, "")
                    ),
                }
                for log_id, (types, patterns) in zip(
                    log_ids, attacks_per_entry, strict=True
                )
                if types
                for attack_type in types
            ]
            if detections:
                session.execute(insert(AttackDetection), detections)

            session.commit()
            return len(logs)

        except Exception as e:
            session.rollback()
            applogger.error(
                f"Error flushing access log buffer ({len(entries)} entries): {e}"
            )
            # Re-queue failed entries so they aren't lost
            global _buffer_bytes
            with _write_lock:
                _write_buffer.extendleft(reversed(entries))
                _buffer_bytes += sum(_entry_bytes(e) for e in entries)
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

        # A never-before-seen IPv6 address gets no row until it comes back:
        # rotating proxy pools mint one address per request and never reuse it,
        # which was 42% of this table. Suspicious traffic is exempt, so nothing
        # worth investigating is dropped. See ip_utils.defer_persist.
        if ip_stats is None and defer_persist(
            sanitized_ip, is_suspicious, is_honeypot_trigger
        ):
            return 0, False, False

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
                ip_stats.ban_multiplier = _ban_multiplier_for(ip_stats.total_violations)
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
                ip_stats.ban_multiplier = _ban_multiplier_for(ip_stats.total_violations)
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
