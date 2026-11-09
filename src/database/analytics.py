"""Aggregate analytics queries.

Top-N rankings, attack-type statistics, cross-table search, and
metrics-summary persistence. All read-only except upsert_metrics_summary.
"""

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import and_, func, or_
from sqlalchemy.orm import joinedload

import detection
from attack_colours import attack_band, colour_map
from dashboard_cache import (
    SLOW_TABLE_TTL,
    get_cached_table,
    pagination,
    set_cached_table,
    table_row_count,
)
from database.text_filters import access_log_text_clauses
from logger import get_app_logger
from models import (
    AccessLog,
    AttackDetection,
    GeneratedPage,
    IpStats,
    MetricsSummary,
)
from period import SLOT_FMT, parse_slot, range_conditions, resolve_period, slot_labels

if TYPE_CHECKING:
    from database.core import DatabaseManager

_BAND_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _types_in_bands(session, since, until, bands) -> list[str]:
    """Attack types seen in [since, until) whose severity band is in bands."""
    q = session.query(AttackDetection.attack_type).join(
        AccessLog, AccessLog.id == AttackDetection.access_log_id
    )
    if since:
        q = q.filter(AccessLog.timestamp >= since)
    if until:
        q = q.filter(AccessLog.timestamp < until)
    return [t for (t,) in q.distinct() if attack_band(t) in bands]


def _rule_match(rule: str):
    """Detections of this rule, crediting legacy unnamed rows to its sole type."""
    match = AttackDetection.rule_name == rule
    sole_type = detection.sole_rule_type(rule)
    if sole_type:
        match = or_(
            match,
            and_(
                AttackDetection.rule_name.is_(None),
                AttackDetection.attack_type == sole_type,
            ),
        )
    return match


applogger = get_app_logger()

# Newest detections a text-filtered attack count looks at.
COUNT_WINDOW = 5000


# Cached by user_agent_counts(); the warmup refreshes it on its slow run.
UA_ROLLUP_KEY = "user_agents:rollup"


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
            count_col = func.count()
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

    def user_agent_counts(self, refresh: bool = False) -> list[list]:
        """Every user agent with its request count. Few distinct values over many
        rows, so one cached scan serves every sort, search and page."""
        rows = None if refresh else get_cached_table(UA_ROLLUP_KEY)
        if rows is None:
            session = self._db.session
            try:
                rows = [
                    [ua, n]
                    for ua, n in session.query(AccessLog.user_agent, func.count())
                    .filter(
                        AccessLog.user_agent.isnot(None), AccessLog.user_agent != ""
                    )
                    .group_by(AccessLog.user_agent)
                ]
            finally:
                self._db.close_session()
            set_cached_table(UA_ROLLUP_KEY, rows, ttl=SLOW_TABLE_TTL)
        return rows

    def get_top_user_agents(self, limit: int = 10, min_count: int = 1) -> list[tuple]:
        """Top user agents as (user_agent, count), most requests first."""
        rows = [r for r in self.user_agent_counts() if r[1] >= min_count]
        rows.sort(key=lambda r: (-r[1], r[0]))
        return [(ua, n) for ua, n in rows[:limit]]

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
            # Unfiltered, an exact count walks all of ip_stats on every page.
            if search:
                total_ips = count_q.scalar() or 0
            elif categories:
                count_key = f"top_ips:count:{','.join(sorted(categories))}"
                total_ips = get_cached_table(count_key)
                if total_ips is None:  # 0 is a valid count
                    total_ips = count_q.scalar() or 0
                    set_cached_table(count_key, total_ips)
            else:
                total_ips = table_row_count(session, IpStats)

            if sort_by == "count":
                order_col = IpStats.total_requests
            else:
                order_col = IpStats.ip

            if sort_order == "desc":
                base_query = base_query.order_by(order_col.desc())
            else:
                base_query = base_query.order_by(order_col.asc())

            results = base_query.offset(offset).limit(page_size).all()

            return {
                "ips": [
                    {
                        "ip": row.ip,
                        "count": row.total_requests,
                        "category": row.category or "unknown",
                    }
                    for row in results
                ],
                "pagination": pagination(page, page_size, total_ips),
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
            count_col = func.count().label("count")

            path_expr = AccessLog.path.label("path")

            search_filter = []
            if search:
                search_filter.append(AccessLog.path.ilike(f"%{search}%"))
            if honeypot_only:
                search_filter.append(AccessLog.is_honeypot_trigger)

            # Count distinct paths that meet the min_count threshold
            count_subq = (
                session.query(path_expr)
                .filter(*search_filter)
                .group_by(path_expr)
                .having(func.count() >= min_count)
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
                .having(func.count() >= min_count)
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

            return {
                "paths": [{"path": row.path, "count": row.count} for row in results],
                "pagination": pagination(page, page_size, int(total_paths)),
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
        """A page of user agents by count or name, filtered by a substring."""
        needle = (search or "").casefold()
        rows = [
            r
            for r in self.user_agent_counts()
            if r[1] >= min_count and needle in r[0].casefold()
        ]
        rows.sort(key=lambda r: r[0])
        if sort_by == "count":
            rows.sort(key=lambda r: r[1], reverse=sort_order == "desc")
        elif sort_order == "desc":
            rows.reverse()
        start = (page - 1) * page_size
        return {
            "user_agents": [
                {"user_agent": ua, "count": n}
                for ua, n in rows[start : start + page_size]
            ],
            "pagination": pagination(page, page_size, len(rows)),
        }

    def get_attackers_in_period(
        self,
        since: datetime | None,
        until: datetime | None,
        attack_type: str | None = None,
        rule: str | None = None,
        page: int = 1,
        page_size: int = 10,
        severities: list[str] | None = None,
        search: str | None = None,
        exclude: list[str] | None = None,
        method_filter: str | None = None,
        ip_filter: str | None = None,
    ) -> dict[str, Any]:
        """IPs ranked by matching detections in the window, whatever their category."""
        session = self._db.session
        try:
            conds = [AttackDetection.access_log_id == AccessLog.id]
            if since:
                conds.append(AccessLog.timestamp >= since)
            if until:
                conds.append(AccessLog.timestamp < until)
            conds += access_log_text_clauses(search, exclude, method_filter, ip_filter)
            matching = list(conds)
            if attack_type:
                matching.append(AttackDetection.attack_type == attack_type)
            if rule:
                matching.append(_rule_match(rule))
            if severities:
                banded = _types_in_bands(session, since, until, severities)
                matching.append(AttackDetection.attack_type.in_(banded))
            grouped = (
                session.query(
                    AccessLog.ip.label("ip"),
                    func.count(AttackDetection.id).label("hits"),
                    func.max(AccessLog.timestamp).label("last_seen"),
                )
                .select_from(AttackDetection)
                .join(AccessLog, AccessLog.id == AttackDetection.access_log_id)
                .filter(*matching[1:])
                .group_by(AccessLog.ip)
            )
            total = grouped.count()
            rows = (
                grouped.order_by(func.count(AttackDetection.id).desc(), AccessLog.ip)
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            ips = [r.ip for r in rows]
            types: dict[str, dict[str, int]] = {}
            info = {}
            if ips:
                type_q = (
                    session.query(
                        AccessLog.ip, AttackDetection.attack_type, func.count()
                    )
                    .select_from(AttackDetection)
                    .join(AccessLog, AccessLog.id == AttackDetection.access_log_id)
                    .filter(*conds[1:], AccessLog.ip.in_(ips))
                    .group_by(AccessLog.ip, AttackDetection.attack_type)
                )
                for ip, atype, n in type_q:
                    types.setdefault(ip, {})[atype] = n
                info = {
                    i.ip: i for i in session.query(IpStats).filter(IpStats.ip.in_(ips))
                }
            attackers = []
            for r in rows:
                by_type = types.get(r.ip, {})
                stats = info.get(r.ip)
                attackers.append(
                    {
                        "ip": r.ip,
                        "hits": r.hits,
                        "top_type": (
                            max(by_type, key=lambda t: (by_type[t], t))
                            if by_type
                            else None
                        ),
                        "worst_band": min(
                            (attack_band(t) for t in by_type),
                            key=_BAND_RANK.get,
                            default="low",
                        ),
                        "category": stats.category if stats else None,
                        "last_seen": r.last_seen,
                        "city": stats.city if stats else None,
                        "country_code": stats.country_code if stats else None,
                    }
                )
            return {
                "attackers": attackers,
                "pagination": pagination(page, page_size, total),
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
        search: str | None = None,
        method_filter: str | None = None,
        total: int | None = None,
        exclude: list[str] | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        rule_filter: str | None = None,
        severity_filter: list[str] | None = None,
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
            search: Optional case-insensitive substring filter across IP/path/user-agent
            method_filter: Optional HTTP method filter (e.g. GET, POST)
            exclude: Case-insensitive substrings; requests whose IP, path or
                user agent contains any of them are left out

        Returns:
            Dictionary with attacks list and pagination info
        """
        session = self._db.session
        try:
            offset = (page - 1) * page_size

            # Validate sort parameters
            valid_sort_fields = {
                "timestamp",
                "ip",
                "attack_type",
                "request_size",
                "method",
            }
            sort_by = sort_by if sort_by in valid_sort_fields else "timestamp"
            sort_order = (
                sort_order.lower() if sort_order.lower() in {"asc", "desc"} else "desc"
            )

            # An access log matches if it has at least one attack detection.
            # We express that with EXISTS rather than JOIN + GROUP BY: the
            # detection predicate (and any attack_type filter) stays inside the
            # correlated subquery against the indexed attack_detections.access_log_id,
            # while the outer scan over access_logs is driven by the
            # ix_access_logs_timestamp index. That lets the database satisfy
            # ORDER BY timestamp ... LIMIT by walking the index newest-first and
            # stopping early, instead of materializing every match into a temp
            # B-tree to sort (the cost of the previous GROUP BY form).
            detection_filters = []
            if attack_type_filter:
                detection_filters.append(
                    AttackDetection.attack_type == attack_type_filter
                )
            if rule_filter:
                detection_filters.append(_rule_match(rule_filter))
            if severity_filter:
                types = _types_in_bands(session, since, until, severity_filter)
                detection_filters.append(AttackDetection.attack_type.in_(types))
            detection_exists = session.query(AttackDetection.id).filter(
                AttackDetection.access_log_id == AccessLog.id, *detection_filters
            )
            match_filters = [detection_exists.exists()]
            if since:
                match_filters.append(AccessLog.timestamp >= since)
            if until:
                match_filters.append(AccessLog.timestamp < until)
            # Detection-side filters need the exact EXISTS count, not the shortcuts.
            narrowed = bool(since or until or rule_filter or severity_filter)
            match_filters += access_log_text_clauses(
                search, exclude, method_filter, ip_filter
            )

            # Unfiltered, count from attack_detections alone (10.9s -> 0.26s).
            capped = False
            if total is not None:
                total_attacks = total
            elif (
                (search or exclude or method_filter) and not ip_filter and not narrowed
            ):
                # Unindexed text filters: an exact count reads every attack
                # row's heap tuple (28s on the demo). Count within the newest
                # COUNT_WINDOW detections instead, a lower bound once full.
                window = session.query(AttackDetection.access_log_id).order_by(
                    AttackDetection.access_log_id.desc()
                )
                if attack_type_filter:
                    window = window.filter(
                        AttackDetection.attack_type == attack_type_filter
                    )
                window = window.limit(COUNT_WINDOW).subquery()
                total_attacks = (
                    session.query(func.count(func.distinct(AccessLog.id)))
                    .filter(AccessLog.id.in_(session.query(window.c.access_log_id)))
                    .filter(*match_filters[1:])
                    .scalar()
                    or 0
                )
                capped = (
                    session.query(func.count()).select_from(window).scalar()
                    >= COUNT_WINDOW
                )
            elif len(match_filters) == 1 and not narrowed:
                count_q = session.query(
                    func.count(func.distinct(AttackDetection.access_log_id))
                )
                if attack_type_filter:
                    count_q = count_q.filter(
                        AttackDetection.attack_type == attack_type_filter
                    )
                total_attacks = count_q.scalar() or 0
            else:
                # From the detections, not EXISTS: the planner seq-scans the
                # log for a wide period (11s vs 0.1s on the demo).
                total_attacks = (
                    session.query(
                        func.count(func.distinct(AttackDetection.access_log_id))
                    )
                    .join(AccessLog, AccessLog.id == AttackDetection.access_log_id)
                    .filter(*detection_filters, *match_filters[1:])
                    .scalar()
                    or 0
                )

            # Order column lives on AccessLog (timestamp default; ip/size optional),
            # so the outer query can be ordered and limited directly.
            if sort_by == "ip":
                order_col = AccessLog.ip
            elif sort_by == "method":
                order_col = AccessLog.method
            elif sort_by == "request_size":
                order_col = func.length(AccessLog.raw_request)
            else:
                order_col = AccessLog.timestamp
            order_expr = order_col.desc() if sort_order == "desc" else order_col.asc()
            # A filtered view is few rows reached from the detections, and its
            # matches can all be old: coalesce keeps it off the sort index.
            # Only the timestamp walk meets recent attacks early (ip: 24s).
            may_walk = (
                sort_by == "timestamp"
                and not detection_filters
                and len(match_filters) == 1
            )
            page_col = order_col if may_walk else func.coalesce(order_col, order_col)
            page_expr = page_col.desc() if sort_order == "desc" else page_col.asc()

            # Two-step load: page the matching ids first (index-driven, no
            # collection join), then eager-load attack_detections for just that
            # page. This keeps joinedload + LIMIT correct (limiting a collection
            # join directly can truncate the eager-loaded rows).
            # Every attack log is suspicious (tracker), so this walks the small
            # ix_access_logs_suspicious_timestamp instead of all of access_logs.
            paginated_ids = (
                session.query(AccessLog.id)
                .filter(AccessLog.is_suspicious, *match_filters)
                .order_by(page_expr)
                .offset(offset)
                .limit(page_size)
                .subquery()
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
                    "method": log.method,
                    "path": log.path,
                    "user_agent": log.user_agent,
                    "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                    "attack_types": [d.attack_type for d in log.attack_detections],
                    "tlsh_hash": next(
                        (d.tlsh_hash for d in log.attack_detections if d.tlsh_hash),
                        None,
                    ),
                    "cluster_id": next(
                        (d.cluster_id for d in log.attack_detections if d.cluster_id),
                        None,
                    ),
                    "request_size": len(log.raw_request) if log.raw_request else 0,
                    "raw_request": log.raw_request,  # Keep for backward compatibility
                }
                for log in logs
            ]
            hashes = self._db.payloads.rep_hash_map(
                {r["cluster_id"] for r in paginated if r["cluster_id"]}
            )
            for row in paginated:
                row["cluster_hash"] = (hashes.get(row["cluster_id"]) or "")[:12]

            return {
                "attacks": paginated,
                "pagination": {
                    **pagination(page, page_size, total_attacks),
                    "capped": capped,
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
                ],
                "colours": colour_map(row.attack_type for row in results),
            }
        finally:
            self._db.close_session()

    def get_attack_facets(
        self,
        since: datetime | None = None,
        until: datetime | None = None,
        search: str | None = None,
        exclude: list[str] | None = None,
        method_filter: str | None = None,
        ip_filter: str | None = None,
    ) -> dict[str, Any]:
        """Detections per severity band and per rule within [since, until)."""
        session = self._db.session
        try:
            q = session.query(
                AttackDetection.rule_name,
                AttackDetection.attack_type,
                func.count(AttackDetection.id),
            ).join(AccessLog, AccessLog.id == AttackDetection.access_log_id)
            if since:
                q = q.filter(AccessLog.timestamp >= since)
            if until:
                q = q.filter(AccessLog.timestamp < until)
            q = q.filter(
                *access_log_text_clauses(search, exclude, method_filter, ip_filter)
            )
            rows = q.group_by(AttackDetection.rule_name, AttackDetection.attack_type)
            coordinator = detection.loaded_detection()
            sole = {}  # attack_type -> its only loaded rule
            if coordinator:
                sole = {
                    t: r[0]["rule"]
                    for t, r in coordinator.yara.rule_details.items()
                    if len(r) == 1
                }
            severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            rules: dict[str, dict] = {}
            for rule, attack_type, hits in rows:
                band = attack_band(attack_type)
                severities[band] += hits
                rule = rule or sole.get(attack_type)
                if not rule:
                    continue
                entry = rules.setdefault(
                    rule,
                    {
                        "rule": rule,
                        "attack_type": attack_type,
                        "band": band,
                        "hits": 0,
                    },
                )
                entry["hits"] += hits
                if rule == "credential_fields":
                    entry["label"] = "Credential capture"
            return {
                "severities": severities,
                "rules": sorted(rules.values(), key=lambda r: -r["hits"]),
            }
        finally:
            self._db.close_session()

    def get_attack_types_daily(
        self,
        limit: int = 10,
        days: int = 30,
        offset_days: int = 0,
        slot: str | None = None,
        search: str | None = None,
        exclude: list[str] | None = None,
        method_filter: str | None = None,
        ip_filter: str | None = None,
    ) -> dict[str, Any]:
        """Top attack types per 1h/4h/1d bucket over the window, plus per-slot totals."""
        session = self._db.session
        try:
            period = resolve_period(days, offset_days)
            labels = slot_labels(period)
            bh = period.bucket_hours
            out = {
                "attack_types": [],
                "dates": labels,
                "bucket_hours": bh,
                "slot_totals": None,
                "colours": {},
            }
            text = access_log_text_clauses(search, exclude, method_filter, ip_filter)
            time_filter = (
                range_conditions(AccessLog.timestamp, period.since, period.until) + text
            )

            top = (
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
            names = [r.attack_type for r in top]

            if names:
                if "sqlite" in str(session.bind.url):
                    hour_expr = func.strftime("%Y-%m-%dT%H", AccessLog.timestamp)
                else:
                    hour_expr = func.to_char(AccessLog.timestamp, 'YYYY-MM-DD"T"HH24')
                rows = (
                    session.query(
                        AttackDetection.attack_type,
                        hour_expr.label("hour"),
                        func.count(AttackDetection.id).label("count"),
                    )
                    .join(AccessLog, AttackDetection.access_log_id == AccessLog.id)
                    .filter(*time_filter, AttackDetection.attack_type.in_(names))
                    .group_by(AttackDetection.attack_type, hour_expr)
                    .all()
                )
                data = {t: dict.fromkeys(labels, 0) for t in names}
                for r in rows:
                    h = parse_slot(str(r.hour))
                    if h is None:
                        continue
                    h -= timedelta(hours=h.hour % bh)
                    key = h.strftime(SLOT_FMT)
                    if key in data[r.attack_type]:
                        data[r.attack_type][key] += r.count
                out["attack_types"] = [
                    {
                        "type": r.attack_type,
                        "total": r.total,
                        "daily": [data[r.attack_type][d] for d in labels],
                    }
                    for r in top
                ]

            types = set(names)
            sp = resolve_period(days, offset_days, slot)
            if sp.slot:
                totals = (
                    session.query(
                        AttackDetection.attack_type,
                        func.count(AttackDetection.id).label("total"),
                    )
                    .join(AccessLog, AttackDetection.access_log_id == AccessLog.id)
                    .filter(
                        *range_conditions(AccessLog.timestamp, sp.since, sp.until),
                        *text,
                    )
                    .group_by(AttackDetection.attack_type)
                    .order_by(func.count(AttackDetection.id).desc())
                    .all()
                )
                out["slot_totals"] = [
                    {"type": r.attack_type, "total": r.total} for r in totals
                ]
                types |= {r.attack_type for r in totals}
            out["colours"] = colour_map(types)
            return out
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
                    "method": log.method,
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

            ip_rows = (
                # + 0: a rare term must not walk the whole total_requests index;
                # the window count saves a second scan of ip_stats.
                ip_query.add_columns(func.count().over())
                .order_by((IpStats.total_requests + 0).desc())
                .offset(offset)
                .limit(page_size)
                .all()
            )
            ips = [row[0] for row in ip_rows]
            total_ips = ip_rows[0][1] if ip_rows else 0
            if not ip_rows and page > 1:
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
