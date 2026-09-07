#!/usr/bin/env python3

"""
Queries and inserts over captured_payloads (files/uploaded payloads) plus
referer-history reads over access_logs for the IP Insight and Threat tabs.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote

from sqlalchemy import func, select

from dashboard_cache import pagination
from logger import get_app_logger
from models import AccessLog, AttackDetection, CapturedPayload, PayloadCluster
from sanitizer import sanitize_ip
from tlsh_utils import SIMILARITY_THRESHOLD, tlsh_diff

if TYPE_CHECKING:
    from database.core import DatabaseManager


def _request_body(raw_request: str | None) -> str | None:
    """Decoded request body (headers stripped, URL-unescaped) for inline
    display in the campaign dive, or None when absent."""
    if not raw_request:
        return None
    body = raw_request.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in raw_request else ""
    return unquote(body) if body else None


def _scalar_min_max(db) -> tuple[Any, Any]:
    """Two-argument scalar min/max: sqlite's func.min(col, val) works, but
    postgres only has aggregate min/max and needs LEAST/GREATEST instead."""
    if db.engine.dialect.name == "postgresql":
        return func.least, func.greatest
    return func.min, func.max


applogger = get_app_logger()

# Hashed events pulled into memory per similarity lookup, newest first. TLSH
# distance can't be expressed in SQL, so the diff runs in Python — without a cap
# a single dashboard click read every hashed row in the database.
MAX_CANDIDATES = 5000


class PayloadRepo:
    """Reads and writes captured file payloads, plus referer-history reads."""

    def __init__(self, db: "DatabaseManager") -> None:
        self._db = db

    # ---- Writes ----

    def add_payload(
        self,
        access_log_id: int,
        ip: str,
        filename: str | None,
        content_type: str | None,
        size: int,
        tlsh_hash: str | None,
        sha256: str | None,
    ) -> int | None:
        """Persist one captured file/upload. Returns the new row id or None."""
        session = self._db.session
        try:
            payload = CapturedPayload(
                access_log_id=access_log_id,
                ip=sanitize_ip(ip),
                filename=filename[:255] if filename else None,
                content_type=content_type[:128] if content_type else None,
                size=size,
                tlsh_hash=tlsh_hash,
                sha256=sha256,
            )
            session.add(payload)
            session.commit()
            return payload.id
        except Exception as e:
            session.rollback()
            applogger.error(f"Failed to persist captured payload: {e}")
            return None
        finally:
            self._db.close_session()

    # ---- Reads ----

    def get_by_ip(self, ip: str, page: int = 1, page_size: int = 10) -> dict[str, Any]:
        """Paginated payloads uploaded by a single IP (IP Insight tab)."""
        session = self._db.session
        try:
            q = session.query(CapturedPayload).filter(
                CapturedPayload.ip == sanitize_ip(ip)
            )
            total = q.count()
            rows = (
                q.order_by(CapturedPayload.timestamp.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            payloads = [self._serialize(p) for p in rows]
            hashes = self.rep_hash_map(
                {p["cluster_id"] for p in payloads if p["cluster_id"]}
            )
            for p in payloads:
                p["cluster_hash"] = (hashes.get(p["cluster_id"]) or "")[:12]
            return {
                "payloads": payloads,
                "pagination": pagination(page, page_size, total),
            }
        finally:
            self._db.close_session()

    def rep_hash_map(self, cluster_ids: set[str]) -> dict[str, str]:
        """Map campaign cluster ids to their representative hash."""
        session = self._db.session
        try:
            if not cluster_ids:
                return {}
            rows = (
                session.query(PayloadCluster.id, PayloadCluster.representative_hash)
                .filter(PayloadCluster.id.in_(cluster_ids))
                .all()
            )
            return dict(rows)
        finally:
            self._db.close_session()

    def get_global_index(
        self,
        page: int = 1,
        page_size: int = 20,
        filename: str | None = None,
        ip: str | None = None,
        sort_by: str = "last_seen",
    ) -> dict[str, Any]:
        """Global filename index across all IPs (Threat tab).

        Groups by filename, counting distinct source IPs and first/last seen,
        so recurring file names (WebShell/script uploads) surface as campaigns.
        """
        session = self._db.session
        try:
            filename_q = CapturedPayload.filename.isnot(None)
            if filename:
                filename_q = CapturedPayload.filename.ilike(f"%{filename}%")
            ip_q = CapturedPayload.ip == sanitize_ip(ip) if ip else None

            base = (
                session.query(
                    CapturedPayload.filename,
                    func.count(func.distinct(CapturedPayload.ip)).label("distinct_ips"),
                    func.count(CapturedPayload.id).label("total"),
                    func.min(CapturedPayload.timestamp).label("first_seen"),
                    func.max(CapturedPayload.timestamp).label("last_seen"),
                )
                .filter(filename_q)
                .group_by(CapturedPayload.filename)
            )
            if ip_q is not None:
                base = base.filter(ip_q)

            total_rows = base.count()
            valid_sort = {
                "last_seen": func.max(CapturedPayload.timestamp),
                "first_seen": func.min(CapturedPayload.timestamp),
                "filename": CapturedPayload.filename,
                "distinct_ips": func.count(func.distinct(CapturedPayload.ip)),
            }
            order = valid_sort.get(sort_by, valid_sort["last_seen"])
            rows = (
                base.order_by(order.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )

            # access_log_id of the most recent capture per filename, so clicking a
            # filename in the Threats tab can open that payload directly.
            latest = session.query(
                CapturedPayload.filename.label("fname"),
                CapturedPayload.access_log_id.label("log_id"),
                func.row_number()
                .over(
                    partition_by=CapturedPayload.filename,
                    order_by=CapturedPayload.id.desc(),
                )
                .label("rn"),
            ).subquery()
            latest_by_filename = {
                r.fname: r.log_id
                for r in session.query(latest).filter(latest.c.rn == 1).all()
            }

            return {
                "index": [
                    {
                        "filename": r.filename or "(untitled)",
                        "log_id": latest_by_filename.get(r.filename),
                        "distinct_ips": r.distinct_ips,
                        "total": r.total,
                        "first_seen": r.first_seen,
                        "last_seen": r.last_seen,
                    }
                    for r in rows
                ],
                "pagination": pagination(page, page_size, total_rows),
            }
        finally:
            self._db.close_session()

    def get_similar_events(
        self,
        base_hash: str,
        threshold: int = SIMILARITY_THRESHOLD,
        limit: int = 30,
    ) -> list[dict[str, Any]]:
        """Events whose TLSH digest is within `threshold` of base_hash — attack
        request bodies (SQLi/XSS/...) and uploaded files across all IPs.

        A digest of 0 from another IP is an exact copy (the campaign signal) and
        is deliberately kept.
        ponytail: in-Python diff over the MAX_CANDIDATES most recent hashed
        events (TLSH can't be prefiltered in SQL); raise the cap or prefilter by
        hash prefix if older events need to match too.
        """
        session = self._db.session
        try:
            attack_rows = (
                session.query(
                    AttackDetection.tlsh_hash,
                    AttackDetection.attack_type,
                    AttackDetection.matched_pattern,
                    AccessLog.id.label("access_log_id"),
                    AccessLog.ip,
                    AccessLog.path,
                    AccessLog.timestamp,
                )
                .join(AccessLog, AttackDetection.access_log_id == AccessLog.id)
                .filter(AttackDetection.tlsh_hash.isnot(None))
                .order_by(AccessLog.timestamp.desc())
                .limit(MAX_CANDIDATES)
                .all()
            )
            file_rows = (
                session.query(
                    CapturedPayload.tlsh_hash,
                    CapturedPayload.filename,
                    CapturedPayload.ip,
                    CapturedPayload.access_log_id,
                    CapturedPayload.timestamp,
                    CapturedPayload.content_type,
                    CapturedPayload.size,
                )
                .filter(CapturedPayload.tlsh_hash.isnot(None))
                .order_by(CapturedPayload.timestamp.desc())
                .limit(MAX_CANDIDATES)
                .all()
            )

            similar: list[dict[str, Any]] = []
            groups: dict[int, dict[str, Any]] = {}
            for h, atype, pattern, log_id, ip, path, ts in attack_rows:
                d = tlsh_diff(base_hash, h)
                if d is None or d > threshold:
                    continue
                g = groups.get(log_id)
                if g is None:
                    g = groups[log_id] = {
                        "kind": "attack",
                        "diff": d,
                        "attack_types": [],
                        "matched_pattern": [],
                        "filename": None,
                        "ip": ip,
                        "path": path,
                        "access_log_id": log_id,
                        "timestamp": ts,
                        "content_type": None,
                        "size": None,
                    }
                if d < g["diff"]:
                    g["diff"] = d
                g["attack_types"].append(atype)
                if pattern and pattern not in g["matched_pattern"]:
                    g["matched_pattern"].append(pattern)
            for g in groups.values():
                g["attack_type"] = ", ".join(g["attack_types"])
                g["matched_pattern"] = ", ".join(g["matched_pattern"]) or None
            similar += groups.values()
            for fhash, fname, fip, flog_id, fts, ctype, size in file_rows:
                d = tlsh_diff(base_hash, fhash)
                if d is not None and d <= threshold:
                    similar.append(
                        {
                            "kind": "file",
                            "diff": d,
                            "attack_type": "file",
                            "matched_pattern": None,
                            "filename": fname,
                            "ip": fip,
                            "path": None,
                            "access_log_id": flog_id,
                            "timestamp": fts,
                            "content_type": ctype,
                            "size": size,
                        }
                    )
            similar.sort(key=lambda r: r["diff"])
            return similar[:limit]
        finally:
            self._db.close_session()

    def cluster_reps(self) -> list[tuple[str, str]]:
        """(cluster id, representative hash) for every campaign.

        Load once per batch and pass to assign_cluster, so hashing N payloads
        doesn't re-read payload_clusters N times.
        ponytail: whole-table load, and clustering still costs one tlsh_diff per
        (payload, cluster); bucket by hash prefix if the cluster count ever gets
        big enough to matter.
        """
        session = self._db.session
        try:
            return list(
                session.execute(
                    select(PayloadCluster.id, PayloadCluster.representative_hash)
                ).all()
            )
        finally:
            self._db.close_session()

    def assign_cluster(
        self,
        digest: str | None,
        timestamp,
        threshold: int = SIMILARITY_THRESHOLD,
        reps: list[tuple[str, str]] | None = None,
    ) -> str | None:
        """Campaign assignment for one TLSH digest (incremental, O(#clusters)).

        Pulls one representative hash per existing cluster, compares with
        tlsh.diff, and either joins the nearest cluster under `threshold`
        (bumping capture_count / last_seen) or starts a new cluster with
        `digest` as its representative. Returns the cluster id, or None for an
        unclusterable digest (TNULL / already assigned).

        `reps` is an optional caller-cached cluster_reps() list, appended to
        when a new cluster is seeded so a batch stays consistent without
        re-querying.
        ponytail: concurrent writers (scalable mode) could double-create a
        cluster for the same digest; a startup merge pass would tidy that if
        it ever shows up.
        """
        if not digest:
            return None
        session = self._db.session
        try:
            if reps is None:
                reps = session.execute(
                    select(PayloadCluster.id, PayloadCluster.representative_hash)
                ).all()
            match_id, best = None, None
            for cid, rep in reps:
                d = tlsh_diff(digest, rep)
                if d is not None and d <= threshold and (best is None or d < best):
                    best, match_id = d, cid
            if match_id:
                smin, smax = _scalar_min_max(self._db)
                session.execute(
                    PayloadCluster.__table__.update()
                    .where(PayloadCluster.id == match_id)
                    .values(
                        # Backfilled (past-dated) members may arrive after the
                        # cluster already saw fresher ones; widen the window
                        # instead of blindly overwriting last_seen backward.
                        first_seen=smin(PayloadCluster.first_seen, timestamp),
                        last_seen=smax(PayloadCluster.last_seen, timestamp),
                        capture_count=PayloadCluster.capture_count + 1,
                    )
                )
                session.commit()
                return match_id
            cluster = PayloadCluster(
                representative_hash=digest,
                first_seen=timestamp,
                last_seen=timestamp,
                capture_count=1,
            )
            session.add(cluster)
            session.commit()
            cid = cluster.id
            reps.append((cid, digest))
            return cid
        finally:
            self._db.close_session()

    def get_campaign_clusters(
        self,
        limit: int = 30,
        start: Any = None,
        end: Any = None,
        min_events: int | None = None,
    ) -> list[dict[str, Any]]:
        """Campaign view, one row per payload_clusters entry. Captures/first-last
        come from the cluster row itself (maintained incrementally at ingest);
        distinct IPs and a sample member are pulled live from both member tables.

        With ``start``/``end`` (naive datetimes), only campaigns whose activity
        window overlaps the range are returned — used by the Threats tab
        Global/1D/7D/30D filter and the day navigator.

        ``min_events`` hides clusters that never appeared more than that many
        times (config.tlsh_campaign_min_events) so single-shot probes don't
        read as campaigns.
        """
        if min_events is None:
            from config import get_config

            min_events = get_config().tlsh_campaign_min_events
        session = self._db.session
        try:
            cluster_q = session.query(PayloadCluster).filter(
                PayloadCluster.capture_count > min_events
            )
            if start is not None and end is not None:
                cluster_q = cluster_q.filter(
                    PayloadCluster.last_seen >= start,
                    PayloadCluster.first_seen < end,
                )
            clusters = {
                row.id: {
                    "id": row.id,
                    "rep_hash": row.representative_hash,
                    "first_seen": row.first_seen,
                    "last_seen": row.last_seen,
                    "events": row.capture_count,
                    "ips": 0,
                    "sources": set(),
                    "sample": None,
                    "path": None,
                    "types": {},
                    "top_path": None,
                    "top_path_cnt": 0,
                }
                for row in cluster_q.all()
            }
            if not clusters:
                return []
            cluster_ids = list(clusters)

            # Window predicates: when start/end are set, the detail aggregates
            # below scope to members whose own timestamp falls in the range
            # (bucket via the timestamp index, not a scan of clustered history).
            attack_win = (
                [AccessLog.timestamp >= start, AccessLog.timestamp < end]
                if start is not None and end is not None
                else []
            )
            files_win = (
                [CapturedPayload.timestamp >= start, CapturedPayload.timestamp < end]
                if start is not None and end is not None
                else []
            )

            # Every member read below aggregates in SQL and is restricted to the
            # clusters actually being rendered: pulling one row per member and
            # folding it in Python meant transferring the whole clustered
            # history (including clusters under min_events) on each request.
            for cid, fname in (
                session.query(
                    CapturedPayload.cluster_id, func.min(CapturedPayload.filename)
                )
                .filter(CapturedPayload.cluster_id.in_(cluster_ids), *files_win)
                .group_by(CapturedPayload.cluster_id)
                .all()
            ):
                c = clusters[cid]
                c["sources"].add("files")
                c["sample"] = c["sample"] or fname
                c["path"] = c["path"] or fname

            pattern_q = session.query(
                AttackDetection.cluster_id, func.min(AttackDetection.matched_pattern)
            )
            if attack_win:
                pattern_q = pattern_q.join(
                    AccessLog, AttackDetection.access_log_id == AccessLog.id
                )
            for cid, pattern in (
                pattern_q.filter(
                    AttackDetection.cluster_id.in_(cluster_ids),
                    AttackDetection.matched_pattern.isnot(None),
                    *attack_win,
                )
                .group_by(AttackDetection.cluster_id)
                .all()
            ):
                c = clusters[cid]
                c["sources"].add("attacks")
                c["sample"] = c["sample"] or pattern

            # Distinct IPs per cluster across both member tables — UNION so an
            # IP seen in both is counted once (what the two Python sets did).
            files_ips = select(
                CapturedPayload.cluster_id.label("cid"),
                CapturedPayload.ip.label("ip"),
            ).where(CapturedPayload.cluster_id.in_(cluster_ids), *files_win)
            attack_ips = (
                select(
                    AttackDetection.cluster_id.label("cid"), AccessLog.ip.label("ip")
                )
                .join(AccessLog, AttackDetection.access_log_id == AccessLog.id)
                .where(AttackDetection.cluster_id.in_(cluster_ids), *attack_win)
            )
            member_ips = files_ips.union(attack_ips).subquery()
            for cid, ip_count in session.execute(
                select(
                    member_ips.c.cid, func.count(func.distinct(member_ips.c.ip))
                ).group_by(member_ips.c.cid)
            ).all():
                clusters[cid]["ips"] = ip_count

            # Signature mix: distinct attack types with counts, plus the most
            # frequent target path (a campaign can span several paths).
            types_q = session.query(
                AttackDetection.cluster_id,
                AttackDetection.attack_type,
                func.count(),
            )
            if attack_win:
                types_q = types_q.join(
                    AccessLog, AttackDetection.access_log_id == AccessLog.id
                )
            for cid, atype, cnt in (
                types_q.filter(AttackDetection.cluster_id.in_(cluster_ids), *attack_win)
                .group_by(AttackDetection.cluster_id, AttackDetection.attack_type)
                .all()
            ):
                clusters[cid]["types"][atype] = cnt
            for cid, path, cnt in (
                session.query(
                    AttackDetection.cluster_id,
                    AccessLog.path,
                    func.count(),
                )
                .join(AccessLog, AttackDetection.access_log_id == AccessLog.id)
                .filter(AttackDetection.cluster_id.in_(cluster_ids), *attack_win)
                .group_by(AttackDetection.cluster_id, AccessLog.path)
                .all()
            ):
                c = clusters[cid]
                if cnt > c["top_path_cnt"]:
                    c["top_path"] = path
                    c["top_path_cnt"] = cnt

            result = [
                {
                    "id": c["id"],
                    "rep_hash": c["rep_hash"],
                    # File clusters show their filename; attack-only clusters
                    # fall back to the path they hit most.
                    "path": c["path"] or c["top_path"],
                    "top_path": c["top_path"] or c["path"],
                    "attack_types": [
                        t
                        for t, _ in sorted(
                            c["types"].items(), key=lambda kv: (-kv[1], kv[0])
                        )
                    ],
                    "events": c["events"],
                    "ips": c["ips"],
                    "sources": " + ".join(sorted(c["sources"])) or "unlinked",
                    "first_seen": c["first_seen"],
                    "last_seen": c["last_seen"],
                    "sample": c["sample"],
                }
                for c in clusters.values()
            ]
            result.sort(key=lambda c: c["events"], reverse=True)
            return result[:limit]
        finally:
            self._db.close_session()

    def get_cluster_events(
        self, cluster_id: str, limit: int = 30
    ) -> list[dict[str, Any]]:
        """Members of one campaign: file captures and attack request bodies,
        most recent first."""
        session = self._db.session
        try:
            files = (
                session.query(CapturedPayload)
                .filter(CapturedPayload.cluster_id == cluster_id)
                .all()
            )
            attacks = (
                session.query(
                    AttackDetection.attack_type,
                    AttackDetection.access_log_id,
                    AccessLog.ip,
                    AccessLog.path,
                    AccessLog.timestamp,
                    AccessLog.raw_request,
                )
                .join(AccessLog, AttackDetection.access_log_id == AccessLog.id)
                .filter(AttackDetection.cluster_id == cluster_id)
                .all()
            )
            events = [
                {
                    "kind": "file",
                    "attack_type": "file",
                    "filename": p.filename,
                    "ip": p.ip,
                    "path": None,
                    "access_log_id": p.access_log_id,
                    "timestamp": p.timestamp,
                }
                for p in files
            ]
            # One request can trip several detectors (e.g. a multipart upload
            # flagged as sql_injection + command_injection): group by access log
            # into a single row listing every matched attack type.
            groups: dict[int, dict[str, Any]] = {}
            for atype, log_id, ip, path, ts, raw in attacks:
                g = groups.get(log_id)
                if g is None:
                    g = groups[log_id] = {
                        "kind": "attack",
                        "attack_types": [],
                        "filename": None,
                        "ip": ip,
                        "path": path,
                        "access_log_id": log_id,
                        "timestamp": ts,
                        "body": "",
                    }
                g["attack_types"].append(atype)
                if not g["body"]:
                    g["body"] = _request_body(raw)
            for g in groups.values():
                g["attack_type"] = ", ".join(g["attack_types"])
            events += list(groups.values())
            events.sort(key=lambda e: e["timestamp"] or datetime.min, reverse=True)
            return events[:limit]
        finally:
            self._db.close_session()

    def get_referer_history(self, ip: str, limit: int = 50) -> list[dict[str, Any]]:
        """Chronological referer trail for an IP (which bait led to which path)."""
        session = self._db.session
        try:
            rows = (
                session.query(
                    AccessLog.id, AccessLog.referer, AccessLog.path, AccessLog.timestamp
                )
                .filter(
                    AccessLog.ip == sanitize_ip(ip),
                    AccessLog.referer.isnot(None),
                    AccessLog.referer != "",
                )
                .order_by(AccessLog.timestamp.desc())
                .limit(limit)
                .all()
            )
            return [
                {
                    "id": r.id,
                    "referer": r.referer,
                    "path": r.path,
                    "timestamp": r.timestamp,
                }
                for r in rows
            ]
        finally:
            self._db.close_session()

    @staticmethod
    def _serialize(p: CapturedPayload) -> dict[str, Any]:
        return {
            "id": p.id,
            "access_log_id": p.access_log_id,
            "ip": p.ip,
            "filename": p.filename,
            "content_type": p.content_type,
            "size": p.size,
            "tlsh_hash": p.tlsh_hash,
            "cluster_id": p.cluster_id,
            "sha256": p.sha256,
            "timestamp": p.timestamp.isoformat() if p.timestamp else None,
        }
