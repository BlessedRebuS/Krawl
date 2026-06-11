"""Aggregate analytics queries.

Top-N rankings, attack-type statistics, cross-table search, and
metrics-summary persistence. All read-only except upsert_metrics_summary.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import distinct, func, or_
from sqlalchemy.orm import joinedload

from logger import get_app_logger
from models import (
    AccessLog,
    AttackDetection,
    GeneratedPage,
    IpStats,
    MetricsSummary,
)

if TYPE_CHECKING:
    from database.core import DatabaseManager

applogger = get_app_logger()


class AnalyticsRepo:
    """Aggregate/reporting queries across access logs, attacks, and IP stats."""

    def __init__(self, db: "DatabaseManager") -> None:
        self._db = db

    def get_top_ips(self, limit: int = 10) -> list[tuple]:
        """
        Get top IP addresses by access count (excludes local/private IPs and server IP).

        Args:
            limit: Maximum number of results

        Returns:
            List of (ip, count) tuples ordered by count descending
        """
        session = self._db.session
        try:
            from config import get_config

            config = get_config()
            server_ip = config.get_server_ip()

            query = session.query(IpStats.ip, IpStats.total_requests)
            query = self._db._public_ip_filter(query, IpStats.ip, server_ip)
            results = query.order_by(IpStats.total_requests.desc()).limit(limit).all()

            return [(row.ip, row.total_requests) for row in results]
        finally:
            self._db.close_session()

    def get_top_paths(self, limit: int = 10, min_count: int = 1) -> list[tuple]:
        """
        Get top paths by access count.

        Args:
            limit: Maximum number of results
            min_count: Minimum access count threshold (paths below this are excluded)

        Returns:
            List of (path, count) tuples ordered by count descending
        """
        session = self._db.session
        try:
            count_col = func.count(AccessLog.id)
            results = (
                session.query(AccessLog.path, count_col.label("count"))
                .group_by(AccessLog.path)
                .having(count_col >= min_count)
                .order_by(count_col.desc())
                .limit(limit)
                .all()
            )

            return [(row.path, row.count) for row in results]
        finally:
            self._db.close_session()

    def get_top_user_agents(self, limit: int = 10, min_count: int = 1) -> list[tuple]:
        """
        Get top user agents by access count.

        Args:
            limit: Maximum number of results
            min_count: Minimum access count threshold (user agents below this are excluded)

        Returns:
            List of (user_agent, count) tuples ordered by count descending
        """
        session = self._db.session
        try:
            count_col = func.count(AccessLog.id)
            results = (
                session.query(AccessLog.user_agent, count_col.label("count"))
                .filter(AccessLog.user_agent.isnot(None), AccessLog.user_agent != "")
                .group_by(AccessLog.user_agent)
                .having(count_col >= min_count)
                .order_by(count_col.desc())
                .limit(limit)
                .all()
            )

            return [(row.user_agent, row.count) for row in results]
        finally:
            self._db.close_session()

    def get_top_ips_paginated(
        self,
        page: int = 1,
        page_size: int = 5,
        sort_by: str = "count",
        sort_order: str = "desc",
        search: str | None = None,
        categories: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Retrieve paginated list of top IP addresses by access count.

        Uses the IpStats table (which already stores total_requests per IP)
        instead of doing a costly GROUP BY on the large access_logs table.

        Args:
            page: Page number (1-indexed)
            page_size: Number of results per page
            sort_by: Field to sort by (count or ip)
            sort_order: Sort order (asc or desc)
            search: Optional search string to filter IPs
            categories: Optional list of categories to filter by

        Returns:
            Dictionary with IPs list and pagination info
        """
        session = self._db.session
        try:
            from config import get_config

            config = get_config()
            server_ip = config.get_server_ip()

            offset = (page - 1) * page_size

            # Only SELECT needed columns instead of full ORM load
            base_query = session.query(
                IpStats.ip, IpStats.total_requests, IpStats.category
            )
            base_query = self._db._public_ip_filter(base_query, IpStats.ip, server_ip)

            if search:
                base_query = base_query.filter(IpStats.ip.ilike(f"%{search}%"))
            if categories:
                base_query = base_query.filter(IpStats.category.in_(categories))

            # Direct count avoids subquery with all columns
            count_q = session.query(func.count(IpStats.ip))
            if server_ip:
                count_q = count_q.filter(IpStats.ip != server_ip)
            if search:
                count_q = count_q.filter(IpStats.ip.ilike(f"%{search}%"))
            if categories:
                count_q = count_q.filter(IpStats.category.in_(categories))
            total_ips = count_q.scalar() or 0

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
            self._db.close_session()

    def get_top_paths_paginated(
        self,
        page: int = 1,
        page_size: int = 5,
        sort_by: str = "count",
        sort_order: str = "desc",
        search: str | None = None,
        honeypot_only: bool = False,
        min_count: int = 1,
    ) -> dict[str, Any]:
        """
        Retrieve paginated list of top paths by access count.

        Groups access logs by path with SQL-level sorting and pagination. Honeypot paths are nearly always <255 chars
        so this gives correct results in practice.

        Args:
            page: Page number (1-indexed)
            page_size: Number of results per page
            sort_by: Field to sort by (count or path)
            sort_order: Sort order (asc or desc)
            search: Optional search string to filter paths
            honeypot_only: If True, only include honeypot-triggered paths
            min_count: Minimum access count threshold (paths below this are excluded)

        Returns:
            Dictionary with paths list and pagination info
        """
        session = self._db.session
        try:
            offset = (page - 1) * page_size
            count_col = func.count(AccessLog.id).label("count")

            path_expr = AccessLog.path.label("path")

            search_filter = [AccessLog.path.ilike(f"%{search}%")] if search else []
            if honeypot_only:
                search_filter.append(AccessLog.is_honeypot_trigger)

            # Count distinct paths that meet the min_count threshold
            count_subq = (
                session.query(path_expr)
                .filter(*search_filter)
                .group_by(path_expr)
                .having(func.count(AccessLog.id) >= min_count)
                .subquery()
            )
            total_paths = (
                session.query(func.count()).select_from(count_subq).scalar() or 0
            )

            # Build query with SQL-level sorting and pagination
            query = (
                session.query(path_expr, count_col)
                .filter(*search_filter)
                .group_by(path_expr)
                .having(func.count(AccessLog.id) >= min_count)
            )

            if sort_by == "count":
                order_expr = (
                    count_col.desc() if sort_order == "desc" else count_col.asc()
                )
            else:
                order_expr = (
                    path_expr.desc() if sort_order == "desc" else path_expr.asc()
                )

            results = query.order_by(order_expr).offset(offset).limit(page_size).all()
            total_pages = max(1, (total_paths + page_size - 1) // page_size)

            return {
                "paths": [{"path": row.path, "count": row.count} for row in results],
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": int(total_paths),
                    "total_pages": total_pages,
                },
            }
        finally:
            self._db.close_session()

    def get_top_user_agents_paginated(
        self,
        page: int = 1,
        page_size: int = 5,
        sort_by: str = "count",
        sort_order: str = "desc",
        search: str | None = None,
        min_count: int = 1,
    ) -> dict[str, Any]:
        """
        Retrieve paginated list of top user agents by access count.

        Groups access logs by user agent with SQL-level sorting and
        index and avoid a full table scan.

        Args:
            page: Page number (1-indexed)
            page_size: Number of results per page
            sort_by: Field to sort by (count or user_agent)
            sort_order: Sort order (asc or desc)
            search: Optional search string to filter user agents
            min_count: Minimum access count threshold (user agents below this are excluded)

        Returns:
            Dictionary with user agents list and pagination info
        """
        session = self._db.session
        try:
            offset = (page - 1) * page_size
            count_col = func.count(AccessLog.id).label("count")

            ua_expr = AccessLog.user_agent.label("user_agent")

            base_filter = [AccessLog.user_agent.isnot(None), AccessLog.user_agent != ""]
            if search:
                base_filter.append(AccessLog.user_agent.ilike(f"%{search}%"))

            # Count distinct user agents that meet the min_count threshold
            count_subq = (
                session.query(ua_expr)
                .filter(*base_filter)
                .group_by(ua_expr)
                .having(func.count(AccessLog.id) >= min_count)
                .subquery()
            )
            total_uas = (
                session.query(func.count()).select_from(count_subq).scalar() or 0
            )

            # Build query with SQL-level sorting and pagination
            query = (
                session.query(ua_expr, count_col)
                .filter(*base_filter)
                .group_by(ua_expr)
                .having(func.count(AccessLog.id) >= min_count)
            )

            if sort_by == "count":
                order_expr = (
                    count_col.desc() if sort_order == "desc" else count_col.asc()
                )
            else:
                order_expr = ua_expr.desc() if sort_order == "desc" else ua_expr.asc()

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
                    "total": int(total_uas),
                    "total_pages": total_pages,
                },
            }
        finally:
            self._db.close_session()

    def get_attack_types_paginated(
        self,
        page: int = 1,
        page_size: int = 5,
        sort_by: str = "timestamp",
        sort_order: str = "desc",
        ip_filter: str | None = None,
        attack_type_filter: str | None = None,
    ) -> dict[str, Any]:
        """
        Retrieve paginated list of detected attack types with access logs.

        Args:
            page: Page number (1-indexed)
            page_size: Number of results per page
            sort_by: Field to sort by (timestamp, ip, attack_type)
            sort_order: Sort order (asc or desc)
            ip_filter: Optional IP address to filter results
            attack_type_filter: Optional attack type to filter results

        Returns:
            Dictionary with attacks list and pagination info
        """
        session = self._db.session
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
            if attack_type_filter:
                base_filters.append(AttackDetection.attack_type == attack_type_filter)

            # Count total unique access logs with attack detections
            count_q = session.query(func.count(distinct(AccessLog.id))).join(
                AttackDetection
            )
            if base_filters:
                count_q = count_q.filter(*base_filters)
            total_attacks = count_q.scalar() or 0

            # Get distinct matching AccessLog IDs, then load full objects.
            # Avoids DISTINCT ON + ORDER BY conflicts on PostgreSQL.
            if sort_by == "timestamp":
                order_col = AccessLog.timestamp
            elif sort_by == "ip":
                order_col = AccessLog.ip
            else:
                order_col = AccessLog.timestamp

            order_expr = order_col.desc() if sort_order == "desc" else order_col.asc()

            ids_q = (
                session.query(AccessLog.id, order_col)
                .join(AttackDetection)
                .group_by(AccessLog.id, order_col)
            )
            if base_filters:
                ids_q = ids_q.filter(*base_filters)

            paginated_ids = (
                ids_q.order_by(order_expr).offset(offset).limit(page_size).subquery()
            )

            logs = (
                session.query(AccessLog)
                .options(joinedload(AccessLog.attack_detections))
                .join(paginated_ids, AccessLog.id == paginated_ids.c.id)
                .order_by(order_expr)
                .all()
            )

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
            self._db.close_session()

    def get_attack_types_stats(
        self, limit: int = 20, ip_filter: str | None = None
    ) -> dict[str, Any]:
        """
        Get aggregated statistics for attack types (efficient for large datasets).

        Args:
            limit: Maximum number of attack types to return
            ip_filter: Optional IP address to filter results for

        Returns:
            Dictionary with attack type counts
        """
        session = self._db.session
        try:

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
            self._db.close_session()

    def get_attack_types_daily(
        self, limit: int = 10, days: int = 30, offset_days: int = 0
    ) -> dict[str, Any]:
        """
        Get attack type counts for a sliding window (for line chart).
        Uses hourly granularity for spans <= 7 days, daily otherwise.

        Args:
            limit: Max attack types to return
            days: Window size in days
            offset_days: How many days back to shift the window end
                         (0 = ending today, 30 = ending 30 days ago, etc.)

        Returns top N attack types with their breakdown and totals.
        """
        session = self._db.session
        try:
            from datetime import datetime, timedelta

            end = datetime.now() - timedelta(days=offset_days)
            cutoff = end - timedelta(days=days)
            use_hourly = True

            # Time range filter used by both queries
            time_filter = [
                AccessLog.timestamp >= cutoff,
                AccessLog.timestamp <= end,
            ]

            # Get top N attack types by total count in the period
            top_types_q = (
                session.query(
                    AttackDetection.attack_type,
                    func.count(AttackDetection.id).label("total"),
                )
                .join(AccessLog, AttackDetection.access_log_id == AccessLog.id)
                .filter(*time_filter)
                .group_by(AttackDetection.attack_type)
                .order_by(func.count(AttackDetection.id).desc())
                .limit(limit)
                .all()
            )

            if not top_types_q:
                return {"attack_types": [], "dates": []}

            top_type_names = [row.attack_type for row in top_types_q]
            totals = {row.attack_type: row.total for row in top_types_q}

            if use_hourly:
                # Hourly granularity: build list of hour slots
                slots = []
                total_hours = days * 24
                for i in range(total_hours, -1, -1):
                    slot = (end - timedelta(hours=i)).strftime("%Y-%m-%d %H:00")
                    slots.append(slot)

                # Group by date + hour, portable across SQLite and PostgreSQL
                # strftime works on SQLite, to_char on PostgreSQL

                is_sqlite = "sqlite" in str(session.bind.url)
                if is_sqlite:
                    hour_expr = func.strftime("%Y-%m-%d %H:00", AccessLog.timestamp)
                else:
                    hour_expr = func.to_char(AccessLog.timestamp, "YYYY-MM-DD HH24:00")

                hourly_q = (
                    session.query(
                        AttackDetection.attack_type,
                        hour_expr.label("slot"),
                        func.count(AttackDetection.id).label("count"),
                    )
                    .join(AccessLog, AttackDetection.access_log_id == AccessLog.id)
                    .filter(
                        *time_filter,
                        AttackDetection.attack_type.in_(top_type_names),
                    )
                    .group_by(AttackDetection.attack_type, hour_expr)
                    .all()
                )

                slot_data = {t: {s: 0 for s in slots} for t in top_type_names}
                for row in hourly_q:
                    slot_str = str(row.slot)
                    if (
                        row.attack_type in slot_data
                        and slot_str in slot_data[row.attack_type]
                    ):
                        slot_data[row.attack_type][slot_str] = row.count

                return {
                    "attack_types": [
                        {
                            "type": t,
                            "total": totals[t],
                            "daily": [slot_data[t][s] for s in slots],
                        }
                        for t in top_type_names
                    ],
                    "dates": slots,
                }
            else:
                # Daily granularity
                dates = []
                for i in range(days, -1, -1):
                    d = (end - timedelta(days=i)).strftime("%Y-%m-%d")
                    dates.append(d)

                # Get daily breakdown for those types using func.date() for portability
                day_expr = func.date(AccessLog.timestamp)
                daily_q = (
                    session.query(
                        AttackDetection.attack_type,
                        day_expr.label("day"),
                        func.count(AttackDetection.id).label("count"),
                    )
                    .join(AccessLog, AttackDetection.access_log_id == AccessLog.id)
                    .filter(
                        *time_filter,
                        AttackDetection.attack_type.in_(top_type_names),
                    )
                    .group_by(AttackDetection.attack_type, day_expr)
                    .all()
                )

                # Build daily data per attack type
                daily_data = {t: {d: 0 for d in dates} for t in top_type_names}
                for row in daily_q:
                    day_str = (
                        row.day.strftime("%Y-%m-%d")
                        if hasattr(row.day, "strftime")
                        else str(row.day)
                    )
                    if (
                        row.attack_type in daily_data
                        and day_str in daily_data[row.attack_type]
                    ):
                        daily_data[row.attack_type][day_str] = row.count

                return {
                    "attack_types": [
                        {
                            "type": t,
                            "total": totals[t],
                            "daily": [daily_data[t][d] for d in dates],
                        }
                        for t in top_type_names
                    ],
                    "dates": dates,
                }
        finally:
            self._db.close_session()

    def search(
        self,
        query: str,
        page: int = 1,
        page_size: int = 20,
    ) -> dict[str, Any]:
        """
        Search attacks, IPs, and deception pages matching a query string.

        Searches across AttackDetection (attack_type, matched_pattern),
        AccessLog (ip, path), IpStats (ip, city, country, isp, asn_org),
        and GeneratedPage (path).

        Args:
            query: Search term (partial match)
            page: Page number (1-indexed)
            page_size: Results per page

        Returns:
            Dictionary with matching attacks, ips, deception_pages, and pagination info
        """
        session = self._db.session
        try:
            offset = (page - 1) * page_size
            like_q = f"%{query}%"

            # --- Search attacks (AccessLog + AttackDetection) ---
            # Get distinct AccessLog IDs matching the search, then load full objects.
            # This avoids DISTINCT ON + ORDER BY conflicts on PostgreSQL.
            matching_ids_q = (
                session.query(AccessLog.id)
                .join(AttackDetection)
                .filter(
                    or_(
                        AccessLog.ip.like(like_q),
                        AccessLog.path.like(like_q),
                        AttackDetection.attack_type.like(like_q),
                        AttackDetection.matched_pattern.like(like_q),
                    )
                )
                .distinct()
            )

            total_attacks = (
                session.query(func.count())
                .select_from(matching_ids_q.subquery())
                .scalar()
                or 0
            )

            paginated_ids = (
                matching_ids_q.order_by(AccessLog.id.desc())
                .offset(offset)
                .limit(page_size)
                .subquery()
            )

            attack_logs = (
                session.query(AccessLog)
                .options(joinedload(AccessLog.attack_detections))
                .join(paginated_ids, AccessLog.id == paginated_ids.c.id)
                .order_by(AccessLog.timestamp.desc())
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
                    IpStats.ip.like(like_q),
                    IpStats.city.like(like_q),
                    IpStats.country.like(like_q),
                    IpStats.country_code.like(like_q),
                    IpStats.isp.like(like_q),
                    IpStats.asn_org.like(like_q),
                    IpStats.reverse.like(like_q),
                )
            )

            total_ips = (
                session.query(func.count(IpStats.ip))
                .filter(
                    or_(
                        IpStats.ip.like(like_q),
                        IpStats.city.like(like_q),
                        IpStats.country.like(like_q),
                        IpStats.country_code.like(like_q),
                        IpStats.isp.like(like_q),
                        IpStats.asn_org.like(like_q),
                        IpStats.reverse.like(like_q),
                    )
                )
                .scalar()
                or 0
            )
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

            # --- Search Deception Pages (GeneratedPage) ---
            deception_query = session.query(GeneratedPage).filter(
                GeneratedPage.path.like(like_q)
            )

            total_deception_pages = (
                session.query(func.count(GeneratedPage.path))
                .filter(GeneratedPage.path.like(like_q))
                .scalar()
                or 0
            )

            deception_pages = (
                deception_query.order_by(GeneratedPage.last_accessed.desc())
                .offset(offset)
                .limit(page_size)
                .all()
            )

            deception_results = [
                {
                    "path": page.path,
                    "access_count": page.access_count,
                    "created_at": (
                        page.created_at.isoformat() if page.created_at else None
                    ),
                    "last_accessed": (
                        page.last_accessed.isoformat() if page.last_accessed else None
                    ),
                }
                for page in deception_pages
            ]

            total = total_attacks + total_ips + total_deception_pages
            total_pages = max(
                1,
                (max(total_attacks, total_ips, total_deception_pages) + page_size - 1)
                // page_size,
            )

            return {
                "attacks": attacks,
                "ips": ip_results,
                "deception_pages": deception_results,
                "query": query,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total_attacks": total_attacks,
                    "total_ips": total_ips,
                    "total_deception_pages": total_deception_pages,
                    "total": total,
                    "total_pages": total_pages,
                },
            }
        finally:
            self._db.close_session()

    def upsert_metrics_summary(self, values: dict[tuple, int]) -> None:
        """Persist heavy aggregate counters into metrics_summary.

        Args:
            values: mapping of (metric, label) -> value
        """
        session = self._db.session
        try:
            now = datetime.now()
            for (metric, label), value in values.items():
                row = (
                    session.query(MetricsSummary)
                    .filter(
                        MetricsSummary.metric == metric,
                        MetricsSummary.label == (label or ""),
                    )
                    .first()
                )
                if row:
                    row.value = int(value)
                    row.updated_at = now
                else:
                    session.add(
                        MetricsSummary(
                            metric=metric,
                            label=label or "",
                            value=int(value),
                            updated_at=now,
                        )
                    )
            session.commit()
        except Exception as e:
            session.rollback()
            applogger.error(f"Error upserting metrics summary: {e}")
        finally:
            self._db.close_session()

    def get_metrics_summary(self) -> dict[tuple, int]:
        """Load all persisted summary rows as {(metric, label): value}."""
        session = self._db.session
        try:
            rows = session.query(MetricsSummary).all()
            return {(r.metric, r.label or ""): int(r.value) for r in rows}
        except Exception as e:
            applogger.error(f"Error reading metrics summary: {e}")
            return {}
        finally:
            self._db.close_session()

    def get_heavy_summary(self) -> dict[str, int]:
        """Load the persisted heavy-aggregate snapshot as {metric: value}.

        Only the cumulative current-snapshot rows (empty label); excludes the
        '_deleted' tally rows.
        """
        session = self._db.session
        try:
            rows = (
                session.query(MetricsSummary).filter(MetricsSummary.label == "").all()
            )
            return {r.metric: int(r.value) for r in rows}
        except Exception as e:
            applogger.error(f"Error reading heavy summary: {e}")
            return {}
        finally:
            self._db.close_session()

    def get_deleted_tallies(self) -> dict[str, int]:
        """Load the cumulative 'deleted' tallies as {metric: value}.

        These accumulate what retention removes so reconciliation can keep
        cumulative metrics absolute: reconciled = count(current rows) + tally.
        """
        session = self._db.session
        try:
            rows = (
                session.query(MetricsSummary)
                .filter(MetricsSummary.label == "_deleted")
                .all()
            )
            return {r.metric: int(r.value) for r in rows}
        except Exception as e:
            applogger.error(f"Error reading deleted tallies: {e}")
            return {}
        finally:
            self._db.close_session()
