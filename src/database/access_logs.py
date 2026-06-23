"""Access-log reads, honeypot reads, and dashboard count aggregation.

Writes (persist_access, flush_access_log_buffer) stay on DatabaseManager
as hot paths.
"""

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import distinct, func
from sqlalchemy.orm import joinedload

from logger import get_app_logger
from models import AccessLog, AttackDetection, IpStats
from sanitizer import sanitize_ip

if TYPE_CHECKING:
    from database.core import DatabaseManager

applogger = get_app_logger()


class AccessLogRepo:
    """Reads over access_logs plus honeypot and dashboard aggregations."""

    def __init__(self, db: "DatabaseManager") -> None:
        self._db = db

    def get_paginated(
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
        session = self._db.session
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
            self._db.close_session()

    def get_list(
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
        session = self._db.session
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
            self._db.close_session()

    def get_recent_attacks(self, limit: int = 20) -> list[dict[str, Any]]:
        """
        Get recent access logs that have attack detections.

        Args:
            limit: Maximum number of results

        Returns:
            List of access log dicts with attack_types included
        """
        session = self._db.session
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
            self._db.close_session()

    def get_recent_suspicious(self, limit: int = 20) -> list[dict[str, Any]]:
        """
        Get recent suspicious access attempts (excludes local/private IPs and server IP).

        Args:
            limit: Maximum number of results

        Returns:
            List of access log dictionaries with is_suspicious=True
        """
        session = self._db.session
        try:
            from config import get_config

            config = get_config()
            server_ip = config.get_server_ip()

            query = (
                session.query(AccessLog)
                .filter(AccessLog.is_suspicious)
                .order_by(AccessLog.timestamp.desc())
            )
            query = self._db._public_ip_filter(query, AccessLog.ip, server_ip)
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
            self._db.close_session()

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
        session = self._db.session
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
            base_query = self._db._public_ip_filter(base_query, AccessLog.ip, server_ip)
            base_query = base_query.group_by(AccessLog.ip)

            # Get total count of distinct honeypot IPs
            count_hp = session.query(func.count(distinct(AccessLog.ip))).filter(
                AccessLog.is_honeypot_trigger
            )
            count_hp = self._db._public_ip_filter(count_hp, AccessLog.ip, server_ip)
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
            self._db.close_session()

    def get_honeypot_triggered_ips(self) -> list[tuple]:
        """
        Get IPs that triggered honeypot paths with the paths they accessed
        (excludes local/private IPs and server IP).

        Returns:
            List of (ip, [paths]) tuples
        """
        session = self._db.session
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
            self._db.close_session()

    def get_distinct_paths(self) -> list[str]:
        """Return all distinct request paths (used to seed the unique_paths set)."""
        session = self._db.session
        try:
            from config import get_config

            server_ip = get_config().get_server_ip()
            query = session.query(distinct(AccessLog.path))
            query = self._db._public_ip_filter(query, AccessLog.ip, server_ip)
            return [row[0] for row in query.all() if row[0] is not None]
        except Exception as e:
            applogger.error(f"Error reading distinct paths: {e}")
            return []
        finally:
            self._db.close_session()

    def get_raw_request_by_id(self, log_id: int) -> str | None:
        """
        Retrieve raw HTTP request for a specific access log ID.

        Args:
            log_id: The access log ID

        Returns:
            The raw request string, or None if not found or not available
        """
        session = self._db.session
        try:
            access_log = session.query(AccessLog).filter(AccessLog.id == log_id).first()
            if access_log:
                return access_log.raw_request
            return None
        finally:
            self._db.close_session()

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
            "unique_attackers": self._db.ip_stats.count_category("attacker"),
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
        session = self._db.session
        try:
            from config import get_config

            config = get_config()
            server_ip = config.get_server_ip()

            # --- Fast path: derive from ip_stats (tiny table, one row per IP) ---
            ip_base = session.query(
                func.sum(IpStats.total_requests).label("total_accesses"),
                func.count(IpStats.ip).label("unique_ips"),
            )
            ip_base = self._db._public_ip_filter(ip_base, IpStats.ip, server_ip)
            ip_row = ip_base.one()

            unique_attackers = session.query(func.count(IpStats.ip)).filter(
                IpStats.category == "attacker"
            )
            unique_attackers = self._db._public_ip_filter(
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
            logs_q = self._db._public_ip_filter(logs_q, AccessLog.ip, server_ip)
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
            self._db.close_session()
