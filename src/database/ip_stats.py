"""IP-centric queries.

Enrichment, categorization, reevaluation flags, ban state/overrides,
IP tracking, and attacker / all-IP pagination over the ip_stats,
category_history, and tracked_ips tables.
"""

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import and_, func, or_

from logger import get_app_logger
from models import CategoryHistory, IpStats, TrackedIp
from sanitizer import sanitize_ip

if TYPE_CHECKING:
    from database.core import DatabaseManager

applogger = get_app_logger()

# Mirror of MAX_BAN_EXPONENT in database/core.py (2 ** 10). Used only as a
# coarse lower-bound to bound the timed-out candidate scan.
_MAX_BAN_MULTIPLIER = 1024


class IpStatsRepo:
    """Queries and mutations centered on the ip_stats table."""

    def __init__(self, db: "DatabaseManager") -> None:
        self._db = db

    def is_banned_ip(self, ip: str, ban_duration_seconds: int) -> bool:
        """
        Check if an IP is currently banned.

        Args:
            ip: Client IP address
            ban_duration_seconds: Base ban duration in seconds

        Returns:
            True if the IP is currently banned
        """
        session = self._db.session
        try:
            sanitized_ip = sanitize_ip(ip)
            row = (
                session.query(
                    IpStats.ban_timestamp,
                    IpStats.ban_multiplier,
                    IpStats.page_visit_count,
                )
                .filter(IpStats.ip == sanitized_ip)
                .first()
            )

            if not row or row.ban_timestamp is None:
                return False

            effective_duration = ban_duration_seconds * (row.ban_multiplier or 1)
            elapsed = (datetime.now() - row.ban_timestamp).total_seconds()

            if elapsed > effective_duration:
                # Ban expired — reset count for next cycle
                ip_stats = (
                    session.query(IpStats).filter(IpStats.ip == sanitized_ip).first()
                )
                ip_stats.page_visit_count = 0
                ip_stats.ban_timestamp = None
                session.commit()
                return False

            return True

        except Exception as e:
            applogger.error(f"Error checking ban status for {ip}: {e}")
            return False
        finally:
            self._db.close_session()

    def get_ban_info(self, ip: str, ban_duration_seconds: int) -> dict:
        """
        Get detailed ban information for an IP.

        In scalable mode, results are cached in Redis with a short TTL (30s)
        to avoid hitting the database on every incoming request.

        Args:
            ip: Client IP address
            ban_duration_seconds: Base ban duration in seconds

        Returns:
            Dictionary with ban status details
        """
        from dashboard_cache import get_cached_short, set_cached_short

        sanitized_ip = sanitize_ip(ip)

        # Check Redis short-TTL cache first (scalable mode only)
        cached = get_cached_short(f"ban:{sanitized_ip}")
        if cached is not None:
            return cached

        session = self._db.session
        try:
            # Only fetch the 4 columns needed for ban check (not all 30+)
            row = (
                session.query(
                    IpStats.ban_timestamp,
                    IpStats.total_violations,
                    IpStats.ban_multiplier,
                    IpStats.ban_override,
                    IpStats.timeout_exempt,
                )
                .filter(IpStats.ip == sanitized_ip)
                .first()
            )

            if not row:
                result = {
                    "is_banned": False,
                    "violations": 0,
                    "ban_multiplier": 1,
                    "remaining_ban_seconds": 0,
                }
                set_cached_short(f"ban:{sanitized_ip}", result)
                return result

            (
                ban_timestamp,
                violations_raw,
                multiplier_raw,
                ban_override,
                timeout_exempt,
            ) = row
            violations = violations_raw or 0
            multiplier = multiplier_raw or 1

            # Honour manual ban/unban overrides
            if ban_override is True:
                result = {
                    "is_banned": True,
                    "violations": violations,
                    "ban_multiplier": multiplier,
                    "remaining_ban_seconds": ban_duration_seconds,
                }
                set_cached_short(
                    f"ban:{sanitized_ip}", result, ttl=ban_duration_seconds
                )
                return result
            if ban_override is False:
                result = {
                    "is_banned": False,
                    "violations": violations,
                    "ban_multiplier": multiplier,
                    "remaining_ban_seconds": 0,
                }
                set_cached_short(f"ban:{sanitized_ip}", result)
                return result

            if timeout_exempt:
                result = {
                    "is_banned": False,
                    "violations": violations,
                    "ban_multiplier": multiplier,
                    "remaining_ban_seconds": 0,
                }
                set_cached_short(f"ban:{sanitized_ip}", result)
                return result

            if ban_timestamp is None:
                result = {
                    "is_banned": False,
                    "violations": violations,
                    "ban_multiplier": multiplier,
                    "remaining_ban_seconds": 0,
                }
                set_cached_short(f"ban:{sanitized_ip}", result)
                return result

            effective_duration = ban_duration_seconds * multiplier
            elapsed = (datetime.now() - ban_timestamp).total_seconds()
            remaining = max(0, effective_duration - elapsed)

            result = {
                "is_banned": remaining > 0,
                "violations": violations,
                "ban_multiplier": multiplier,
                "effective_ban_duration_seconds": effective_duration,
                "remaining_ban_seconds": remaining,
            }
            # Cache banned IPs for the remaining ban duration (no need to re-check
            # until the ban expires). Not-banned IPs use the default short TTL.
            cache_ttl = max(int(remaining), 1) if remaining > 0 else None
            set_cached_short(f"ban:{sanitized_ip}", result, ttl=cache_ttl)
            return result

        except Exception as e:
            applogger.error(f"Error getting ban info for {ip}: {e}")
            return {
                "is_banned": False,
                "violations": 0,
                "ban_multiplier": 1,
                "remaining_ban_seconds": 0,
            }
        finally:
            self._db.close_session()

    def set_ban_override(self, ip: str, override: bool | None) -> bool:
        """
        Set ban override for an IP.
        override=True: force into banlist
        override=False: force remove from banlist
        override=None: reset to automatic (category-based)

        Returns True if the IP exists and was updated.
        """
        session = self._db.session
        sanitized_ip = sanitize_ip(ip)
        ip_stats = session.query(IpStats).filter(IpStats.ip == sanitized_ip).first()
        if not ip_stats:
            return False

        ip_stats.ban_override = override
        try:
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            applogger.error(f"Error setting ban override for {sanitized_ip}: {e}")
            return False
        finally:
            self._db.close_session()

    def force_ban(self, ip: str) -> bool:
        """
        Force-ban an IP that may not exist in ip_stats yet.
        Creates a minimal entry if needed.
        """
        session = self._db.session
        sanitized_ip = sanitize_ip(ip)
        ip_stats = session.query(IpStats).filter(IpStats.ip == sanitized_ip).first()
        if not ip_stats:
            ip_stats = IpStats(
                ip=sanitized_ip,
                total_requests=0,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
            )
            session.add(ip_stats)

        ip_stats.ban_override = True
        try:
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            applogger.error(f"Error force-banning {sanitized_ip}: {e}")
            return False
        finally:
            self._db.close_session()

    def set_timeout_exempt(self, ip: str, exempt: bool) -> bool:
        """
        Exempt an IP from (or re-enable) the automatic time-ban.
        exempt=True: the rate-limit 429 is not enforced for this IP.
        exempt=False: reset to automatic timeout behaviour.

        Returns True if the IP exists and was updated.
        """
        from dashboard_cache import delete_cached_short

        session = self._db.session
        sanitized_ip = sanitize_ip(ip)
        ip_stats = session.query(IpStats).filter(IpStats.ip == sanitized_ip).first()
        if not ip_stats:
            return False

        ip_stats.timeout_exempt = exempt
        try:
            session.commit()
            delete_cached_short(f"ban:{sanitized_ip}")
            return True
        except Exception as e:
            session.rollback()
            applogger.error(f"Error setting timeout_exempt for {sanitized_ip}: {e}")
            return False
        finally:
            self._db.close_session()

    def get_ban_overrides_paginated(
        self,
        page: int = 1,
        page_size: int = 25,
    ) -> dict[str, Any]:
        """Get all IPs with a non-null ban_override, paginated."""
        session = self._db.session
        try:
            base_query = session.query(IpStats).filter(IpStats.ban_override.isnot(None))
            total = (
                session.query(func.count(IpStats.ip))
                .filter(IpStats.ban_override.isnot(None))
                .scalar()
                or 0
            )
            total_pages = max(1, (total + page_size - 1) // page_size)

            results = (
                base_query.order_by(IpStats.last_seen.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )

            overrides = []
            for r in results:
                overrides.append(
                    {
                        "ip": r.ip,
                        "ban_override": r.ban_override,
                        "category": r.category,
                        "total_requests": r.total_requests,
                        "country_code": r.country_code,
                        "city": r.city,
                        "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                    }
                )

            return {
                "overrides": overrides,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": total,
                    "total_pages": total_pages,
                },
            }
        finally:
            self._db.close_session()

    def update_ip_stats_analysis(
        self,
        ip: str,
        analyzed_metrics: dict[str, object],
        category: str,
        category_scores: dict[str, int],
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

        session = self._db.session
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
            applogger.info(f"IP: {ip} category has been updated to {category}")

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
        finally:
            self._db.close_session()

    def manual_update_category(self, ip: str, category: str) -> None:
        """
        Update IP category as a result of a manual intervention by an admin

        Args:
            ip: IP address to update
            category: selected category

        """
        session = self._db.session
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
        finally:
            self._db.close_session()

    def _record_category_change(
        self,
        ip: str,
        old_category: str | None,
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
        session = self._db.session
        history_entry = CategoryHistory(
            ip=ip,
            old_category=old_category,
            new_category=new_category,
            timestamp=timestamp,
        )
        session.add(history_entry)

    def get_category_history(self, ip: str) -> list[dict[str, Any]]:
        """
        Retrieve category change history for a specific IP.

        Args:
            ip: IP address to get history for

        Returns:
            List of category change records ordered by timestamp
        """
        session = self._db.session
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
            self._db.close_session()

    def update_ip_rep_infos(
        self,
        ip: str,
        country_code: str,
        asn: str,
        asn_org: str,
        list_on: dict[str, str],
        city: str | None = None,
        latitude: float | None = None,
        longitude: float | None = None,
        country: str | None = None,
        region: str | None = None,
        region_name: str | None = None,
        timezone: str | None = None,
        isp: str | None = None,
        reverse: str | None = None,
        is_proxy: bool | None = None,
        is_hosting: bool | None = None,
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
        session = self._db.session
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
        except Exception:
            session.rollback()
            raise
        finally:
            self._db.close_session()

    def get_unenriched_ips(self, limit: int = 100) -> list[str]:
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

        session = self._db.session
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
                        )
                        .limit(limit)
                        .all()
                    )
                else:
                    raise

            return [ip[0] for ip in ips]
        finally:
            self._db.close_session()

    def get_ips_needing_reevaluation(self) -> list[str]:
        """
        Get all IP addresses that need evaluation.

        Returns:
            List of IP addresses where need_reevaluation is True
            or that have never been analyzed (last_analysis is NULL)
        """
        session = self._db.session
        try:
            ips = (
                session.query(IpStats.ip)
                .filter(
                    or_(
                        IpStats.need_reevaluation,
                        IpStats.last_analysis.is_(None),
                    )
                )
                .all()
            )
            return [ip[0] for ip in ips]
        finally:
            self._db.close_session()

    def flag_stale_ips_for_reevaluation(self) -> int:
        """
        Flag IPs for reevaluation where:
        - last_seen is newer than the configured retention period
        - last_analysis is more than 5 days ago

        Returns:
            Number of IPs flagged for reevaluation
        """
        from config import get_config

        session = self._db.session
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
                    not IpStats.need_reevaluation,
                    not IpStats.manual_category,
                )
                .update(
                    {IpStats.need_reevaluation: True},
                    synchronize_session=False,
                )
            )
            session.commit()
            return count
        except Exception:
            session.rollback()
            raise
        finally:
            self._db.close_session()

    def flag_all_ips_for_reevaluation(self) -> int:
        """
        Flag ALL IPs for reevaluation, regardless of staleness.
        Skips IPs that have a manual category set.

        Returns:
            Number of IPs flagged for reevaluation
        """
        session = self._db.session
        try:
            count = (
                session.query(IpStats)
                .filter(
                    not IpStats.need_reevaluation,
                    not IpStats.manual_category,
                )
                .update(
                    {IpStats.need_reevaluation: True},
                    synchronize_session=False,
                )
            )
            session.commit()
            return count
        except Exception:
            session.rollback()
            raise
        finally:
            self._db.close_session()

    def get_ip_stats(self, limit: int = 100) -> list[dict[str, Any]]:
        """
        Retrieve IP statistics ordered by total requests.

        Args:
            limit: Maximum number of records to return

        Returns:
            List of IP stats dictionaries
        """
        session = self._db.session
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
            self._db.close_session()

    def get_ip_stats_by_ip(self, ip: str) -> dict[str, Any] | None:
        """
        Retrieve IP statistics for a specific IP address.

        In scalable mode, results are cached in Redis with a short TTL (30s)
        to reduce DB load for repeated lookups (e.g. IP category checks on every request).

        Args:
            ip: The IP address to look up

        Returns:
            Dictionary with IP stats or None if not found
        """
        from dashboard_cache import get_cached_short, set_cached_short

        safe_ip = sanitize_ip(ip)

        # Check Redis short-TTL cache first (scalable mode only)
        cached = get_cached_short(f"ipstats:{safe_ip}")
        if cached is not None:
            return cached if cached != "__none__" else None

        session = self._db.session
        try:
            stat = session.query(IpStats).filter(IpStats.ip == safe_ip).first()

            if not stat:
                set_cached_short(f"ipstats:{safe_ip}", "__none__")
                return None

            # Get category history for this IP
            category_history = self.get_category_history(ip)

            result = {
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
            set_cached_short(f"ipstats:{safe_ip}", result)
            return result
        finally:
            self._db.close_session()

    def count_category(self, category: str) -> int:
        """Count the total number of ips in a given category."""
        session = self._db.session
        try:
            count = session.query(IpStats).filter(IpStats.category == category).count()
            return count or 0
        except Exception as e:
            applogger.error(f"Error counting {category}: {e}")
            return 0
        finally:
            self._db.close_session()

    def get_attackers_paginated(
        self,
        page: int = 1,
        page_size: int = 25,
        sort_by: str = "total_requests",
        sort_order: str = "desc",
    ) -> dict[str, Any]:
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
        session = self._db.session
        try:
            offset = (page - 1) * page_size

            # Validate sort parameters
            valid_sort_fields = {"total_requests", "first_seen", "last_seen"}
            sort_by = sort_by if sort_by in valid_sort_fields else "total_requests"
            sort_order = (
                sort_order.lower() if sort_order.lower() in {"asc", "desc"} else "desc"
            )

            # Get total count of attackers (direct count avoids subquery with all columns)
            total_attackers = (
                session.query(func.count(IpStats.ip))
                .filter(IpStats.category == "attacker")
                .scalar()
                or 0
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
            self._db.close_session()

    def get_all_ips_paginated(
        self,
        page: int = 1,
        page_size: int = 25,
        sort_by: str = "total_requests",
        sort_order: str = "desc",
        categories: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Retrieve paginated list of all IPs (or filtered by categories) ordered by specified field.

        Uses column projection to only SELECT the fields needed for map rendering,
        avoiding loading heavy JSON blobs and unused columns from IpStats.

        Args:
            page: Page number (1-indexed)
            page_size: Number of results per page
            sort_by: Field to sort by (total_requests, first_seen, last_seen)
            sort_order: Sort order (asc or desc)
            categories: Optional list of categories to filter by

        Returns:
            Dictionary with IPs list and pagination info
        """
        session = self._db.session
        try:
            offset = (page - 1) * page_size

            # Validate sort parameters
            valid_sort_fields = {"total_requests", "first_seen", "last_seen"}
            sort_by = sort_by if sort_by in valid_sort_fields else "total_requests"
            sort_order = (
                sort_order.lower() if sort_order.lower() in {"asc", "desc"} else "desc"
            )

            # Only SELECT columns needed for map rendering — skip heavy JSON
            # blobs (analyzed_metrics, category_scores, list_on) and unused
            # columns (ban_*, is_proxy, is_hosting, reputation_updated, etc.)
            map_columns = [
                IpStats.ip,
                IpStats.total_requests,
                IpStats.first_seen,
                IpStats.last_seen,
                IpStats.country_code,
                IpStats.city,
                IpStats.latitude,
                IpStats.longitude,
                IpStats.asn,
                IpStats.asn_org,
                IpStats.reputation_score,
                IpStats.reputation_source,
                IpStats.category,
            ]

            query = session.query(*map_columns)
            count_query = session.query(func.count(IpStats.ip))
            if categories:
                query = query.filter(IpStats.category.in_(categories))
                count_query = count_query.filter(IpStats.category.in_(categories))

            # Get total count (direct count avoids subquery with all columns)
            total_ips = count_query.scalar() or 0

            # Apply sorting
            sort_column = {
                "total_requests": IpStats.total_requests,
                "first_seen": IpStats.first_seen,
                "last_seen": IpStats.last_seen,
            }[sort_by]
            query = query.order_by(
                sort_column.desc() if sort_order == "desc" else sort_column.asc()
            )

            # Get paginated IPs
            rows = query.offset(offset).limit(page_size).all()

            total_pages = (total_ips + page_size - 1) // page_size

            return {
                "ips": [
                    {
                        "ip": row.ip,
                        "total_requests": row.total_requests,
                        "first_seen": (
                            row.first_seen.isoformat() if row.first_seen else None
                        ),
                        "last_seen": (
                            row.last_seen.isoformat() if row.last_seen else None
                        ),
                        "country_code": row.country_code,
                        "city": row.city,
                        "latitude": row.latitude,
                        "longitude": row.longitude,
                        "asn": row.asn,
                        "asn_org": row.asn_org,
                        "reputation_score": row.reputation_score,
                        "reputation_source": row.reputation_source,
                        "category": row.category,
                    }
                    for row in rows
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

    def _timedout_candidates(self, session, ban_duration_seconds: int) -> list[IpStats]:
        """
        Rows currently serving an automatic time-ban, newest ban first.

        Currently timed out := ban_timestamp set and within
        ban_duration_seconds * ban_multiplier, ban_override is NULL
        (force ban/unban are shown elsewhere), and not timeout_exempt.

        A coarse SQL lower-bound on ban_timestamp bounds the scan; the exact
        per-row window is computed in Python (dialect-agnostic, mirrors the
        per-request logic in get_ban_info).
        """
        coarse_floor = datetime.now() - timedelta(
            seconds=ban_duration_seconds * _MAX_BAN_MULTIPLIER
        )
        rows = (
            session.query(IpStats)
            .filter(
                IpStats.ban_timestamp.isnot(None),
                IpStats.ban_override.is_(None),
                or_(
                    IpStats.timeout_exempt.is_(None),
                    IpStats.timeout_exempt.is_(False),
                ),
                IpStats.ban_timestamp >= coarse_floor,
            )
            .order_by(IpStats.ban_timestamp.desc())
            .all()
        )
        now = datetime.now()
        live = []
        for r in rows:
            multiplier = r.ban_multiplier or 1
            effective = ban_duration_seconds * multiplier
            elapsed = (now - r.ban_timestamp).total_seconds()
            if elapsed < effective:
                live.append(r)
        return live

    def get_timedout_ips(self, ban_duration_seconds: int) -> list[str]:
        """IP strings currently serving an automatic time-ban (for export)."""
        session = self._db.session
        try:
            return [
                r.ip for r in self._timedout_candidates(session, ban_duration_seconds)
            ]
        finally:
            self._db.close_session()

    def count_timed_out(self, ban_duration_seconds: int) -> int:
        """Count of IPs currently serving an automatic time-ban."""
        session = self._db.session
        try:
            return len(self._timedout_candidates(session, ban_duration_seconds))
        finally:
            self._db.close_session()

    def get_timedout_ips_paginated(
        self,
        ban_duration_seconds: int,
        page: int = 1,
        page_size: int = 25,
    ) -> dict[str, Any]:
        """Paginated view of currently timed-out IPs with remaining time."""
        session = self._db.session
        try:
            candidates = self._timedout_candidates(session, ban_duration_seconds)
            total = len(candidates)
            total_pages = max(1, (total + page_size - 1) // page_size)
            page = max(1, page)
            start = (page - 1) * page_size
            window = candidates[start : start + page_size]

            now = datetime.now()
            items = []
            for r in window:
                multiplier = r.ban_multiplier or 1
                effective = ban_duration_seconds * multiplier
                elapsed = (now - r.ban_timestamp).total_seconds()
                remaining = max(0, int(effective - elapsed))
                items.append(
                    {
                        "ip": r.ip,
                        "remaining_ban_seconds": remaining,
                        "total_violations": r.total_violations or 0,
                        "ban_multiplier": multiplier,
                        "category": r.category,
                        "country_code": r.country_code,
                        "city": r.city,
                        "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                    }
                )

            return {
                "items": items,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": total,
                    "total_pages": total_pages,
                },
            }
        finally:
            self._db.close_session()

    def get_timeout_exempt_paginated(
        self,
        page: int = 1,
        page_size: int = 25,
    ) -> dict[str, Any]:
        """Get all IPs with timeout_exempt=True, paginated."""
        session = self._db.session
        try:
            base_query = session.query(IpStats).filter(IpStats.timeout_exempt.is_(True))
            total = (
                session.query(func.count(IpStats.ip))
                .filter(IpStats.timeout_exempt.is_(True))
                .scalar()
                or 0
            )
            total_pages = max(1, (total + page_size - 1) // page_size)

            results = (
                base_query.order_by(IpStats.last_seen.desc())
                .offset((max(1, page) - 1) * page_size)
                .limit(page_size)
                .all()
            )

            items = []
            for r in results:
                items.append(
                    {
                        "ip": r.ip,
                        "category": r.category,
                        "total_requests": r.total_requests,
                        "country_code": r.country_code,
                        "city": r.city,
                        "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                    }
                )

            return {
                "items": items,
                "pagination": {
                    "page": max(1, page),
                    "page_size": page_size,
                    "total": total,
                    "total_pages": total_pages,
                },
            }
        finally:
            self._db.close_session()

    def get_ips_for_export(self, categories: list[str]) -> list[str]:
        """
        Return IP strings filtered by categories, for banlist export.
        Only SELECT the ip column for minimal overhead.
        Includes force-banned IPs (ban_override=True) regardless of category.
        Excludes force-unbanned IPs (ban_override=False).
        """
        session = self._db.session
        try:
            query = session.query(IpStats.ip).filter(
                or_(
                    and_(
                        IpStats.category.in_(categories),
                        or_(
                            IpStats.ban_override.is_(None),
                            IpStats.ban_override,
                        ),
                    ),
                    IpStats.ban_override,
                )
            )
            return [row.ip for row in query.all()]
        finally:
            self._db.close_session()

    def track_ip(self, ip: str) -> bool:
        """Add an IP to the tracked list with a snapshot of its current stats."""
        session = self._db.session
        sanitized_ip = sanitize_ip(ip)
        existing = session.query(TrackedIp).filter(TrackedIp.ip == sanitized_ip).first()
        if existing:
            return True  # already tracked

        # Snapshot essential data from ip_stats
        stats = session.query(IpStats).filter(IpStats.ip == sanitized_ip).first()
        tracked = TrackedIp(
            ip=sanitized_ip,
            tracked_since=datetime.now(),
            category=stats.category if stats else None,
            total_requests=stats.total_requests if stats else 0,
            country_code=stats.country_code if stats else None,
            city=stats.city if stats else None,
            last_seen=stats.last_seen if stats else None,
        )
        session.add(tracked)
        try:
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            applogger.error(f"Error tracking IP {sanitized_ip}: {e}")
            return False
        finally:
            self._db.close_session()

    def untrack_ip(self, ip: str) -> bool:
        """Remove an IP from the tracked list."""
        session = self._db.session
        sanitized_ip = sanitize_ip(ip)
        tracked = session.query(TrackedIp).filter(TrackedIp.ip == sanitized_ip).first()
        if not tracked:
            return False
        session.delete(tracked)
        try:
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            applogger.error(f"Error untracking IP {sanitized_ip}: {e}")
            return False
        finally:
            self._db.close_session()

    def is_ip_tracked(self, ip: str) -> bool:
        """Check if an IP is currently tracked."""
        session = self._db.session
        sanitized_ip = sanitize_ip(ip)
        try:
            return (
                session.query(TrackedIp).filter(TrackedIp.ip == sanitized_ip).first()
                is not None
            )
        finally:
            self._db.close_session()

    def get_tracked_ips_paginated(
        self,
        page: int = 1,
        page_size: int = 25,
    ) -> dict[str, Any]:
        """Get all tracked IPs, paginated. Reads only from tracked_ips table."""
        session = self._db.session
        try:
            total = session.query(func.count(TrackedIp.ip)).scalar() or 0
            total_pages = max(1, (total + page_size - 1) // page_size)

            tracked_rows = (
                session.query(TrackedIp)
                .order_by(TrackedIp.tracked_since.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )

            items = []
            for t in tracked_rows:
                items.append(
                    {
                        "ip": t.ip,
                        "tracked_since": (
                            t.tracked_since.isoformat() if t.tracked_since else None
                        ),
                        "category": t.category,
                        "total_requests": t.total_requests or 0,
                        "country_code": t.country_code,
                        "city": t.city,
                        "last_seen": t.last_seen.isoformat() if t.last_seen else None,
                    }
                )

            return {
                "tracked_ips": items,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": total,
                    "total_pages": total_pages,
                },
            }
        finally:
            self._db.close_session()
