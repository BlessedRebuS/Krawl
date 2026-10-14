#!/usr/bin/env python3

"""
Crunch similar non-suspicious requests of inactive IPs into one access-log row.

Each path is reduced to a template (Krawl trap links -> /{link}, ids -> {num},
{uuid}, {hex}, {rand}, query values -> {v}); rows of one IP sharing
(method, template, target_host) merge into the lowest-id row, which keeps the
summed hit_count and up to 3 real example paths. See docs/algorithms.md.
"""

import re
from collections import defaultdict
from datetime import datetime

from sqlalchemy import or_

from dashboard_cache import invalidate_table_cache
from database import get_database
from logger import get_app_logger
from sanitizer import MAX_PATH_LENGTH

TASK_CONFIG = {
    "name": "crunch-access-logs",
    # ~285 IPs/s on PostgreSQL: 5000 per run is ~20s, and a 1.5M-IP idle
    # backlog drains in about a day.
    "cron": "*/5 * * * *",
    "enabled": True,
    "run_when_loaded": False,
    # A shared-database rewrite; two pods would merge the same rows.
    "single_pod": True,
}

MAX_SAMPLES = 3

app_logger = get_app_logger()

PLACEHOLDER = re.compile(r"\{[a-z]+\}")
_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
)
_HEX = re.compile(r"[0-9a-f]{8,}", re.IGNORECASE)
_RAND = re.compile(r"[A-Za-z0-9_-]{8,}")
# Readable names (snake_case, kebab-case, or a word-length lowercase run like
# "woocommerce") are probe names, not generated tokens: they stay literal.
_WORDY = re.compile(r"[_-]|[a-z]{5,}")


def _is_trap_link(path: str) -> bool:
    """Krawl homepage link (generative_ai._is_random_link) that also looks random:
    a digit, or an uppercase letter after the first character. The extra rule
    keeps /login, /admin, /Jenkinsfile literal; a few all-lowercase links slip
    through and simply stay uncrunched."""
    from generative_ai import _is_random_link

    segment = path.lstrip("/")
    return _is_random_link(path) and (
        any(c.isdigit() for c in segment) or any(c.isupper() for c in segment[1:])
    )


def _segment_template(segment: str) -> str:
    if not segment or PLACEHOLDER.fullmatch(segment):
        return segment
    stem, dot, ext = segment.rpartition(".")
    if not dot or not stem:  # no extension, or a dotfile like .env
        stem, dot, ext = segment, "", ""
    if _UUID.fullmatch(stem):
        shape = "{uuid}"
    elif stem.isdigit():
        shape = "{num}"
    elif _HEX.fullmatch(stem) and any(c.isdigit() for c in stem):
        shape = "{hex}"
    elif (
        _RAND.fullmatch(stem)
        and any(c.isdigit() for c in stem)
        and any(c.isalpha() for c in stem)
        and not _WORDY.search(stem)
    ):
        shape = "{rand}"
    else:
        return segment
    return shape + dot + ext


def path_template(path: str) -> str:
    """Generic shape of a request path; idempotent."""
    base, sep, query = path.partition("?")
    if _is_trap_link(base):
        base = "/{link}"
    else:
        base = "/".join(_segment_template(s) for s in base.split("/"))
    if sep:
        query = "&".join(
            p.split("=", 1)[0] + "={v}" if "=" in p else p for p in query.split("&")
        )
    return base + sep + query


def _samples(members) -> str | None:
    """Existing samples first (the keeper is lowest id), then new real paths."""
    seen: list[str] = []
    for row in members:
        candidates = row.path_samples.split(", ") if row.path_samples else [row.path]
        for p in candidates:
            if p not in seen and not PLACEHOLDER.search(p):
                seen.append(p)
            if len(seen) == MAX_SAMPLES:
                return ", ".join(seen)[:MAX_PATH_LENGTH]
    return ", ".join(seen)[:MAX_PATH_LENGTH] or None


def _crunch_ip(session, ip: str) -> tuple[int, int]:
    """Merge one IP's similar non-suspicious rows. Returns (groups merged, rows deleted)."""
    from models import AccessLog, AttackDetection, CapturedPayload, RequestAsset

    has_evidence = or_(
        session.query(RequestAsset.id)
        .filter(RequestAsset.access_log_id == AccessLog.id)
        .exists(),
        session.query(CapturedPayload.id)
        .filter(CapturedPayload.access_log_id == AccessLog.id)
        .exists(),
    )
    rows = (
        session.query(AccessLog)
        .filter(
            AccessLog.ip == ip,
            AccessLog.is_suspicious.is_(False),
            AccessLog.is_honeypot_trigger.is_(False),
            ~has_evidence,
        )
        .order_by(AccessLog.id)
        .all()
    )

    from generative_ai import load_robots_disallowed

    # analyze-ips scores robots violations by path prefix, so those paths stay
    # literal; templates can also outgrow the path column ({num} > 1).
    disallows = [d.rstrip("/") for d in load_robots_disallowed() if d.rstrip("/")]
    groups = defaultdict(list)
    for row in rows:
        template = row.path
        if not any(row.path.rstrip("/").startswith(d) for d in disallows):
            template = path_template(row.path)
            if len(template) > MAX_PATH_LENGTH:
                template = row.path
        # user_agent in the key: analyze-ips counts distinct UAs per IP.
        groups[(row.method, template, row.target_host, row.user_agent)].append(row)

    merged = deleted = 0
    for (_, template, _, _), members in groups.items():
        if len(members) == 1 and members[0].path == template:
            continue
        keeper, rest = members[0], members[1:]
        keeper.path_samples = _samples(members)
        keeper.hit_count = sum(m.hit_count or 1 for m in members)
        keeper.timestamp = max(m.timestamp for m in members)
        keeper.path = template
        merged += 1
        if rest:
            # ponytail: one IN list per group; chunk it if an IP ever has
            # more rows in one group than the DB's bound-parameter limit.
            ids = [m.id for m in rest]
            session.query(AttackDetection).filter(
                AttackDetection.access_log_id.in_(ids)
            ).delete(synchronize_session=False)
            session.query(AccessLog).filter(AccessLog.id.in_(ids)).delete(
                synchronize_session=False
            )
            deleted += len(ids)
    return merged, deleted


def main():
    from config import get_config
    from models import IpStats

    config = get_config()
    db = get_database()
    session = db.session
    now = datetime.now()
    cutoff = now - config.retention_crunch_after
    ips_done = groups_merged = rows_deleted = 0
    try:
        ips = [
            row[0]
            for row in session.query(IpStats.ip)
            .filter(
                IpStats.last_seen < cutoff,
                or_(
                    IpStats.crunched_at.is_(None),
                    IpStats.crunched_at < IpStats.last_seen,
                ),
            )
            .order_by(IpStats.last_seen.asc())
            .limit(config.tasks_crunch_ips_batch)
            .all()
        ]
        for ip in ips:
            try:
                merged, deleted = _crunch_ip(session, ip)
                session.query(IpStats).filter(IpStats.ip == ip).update(
                    {IpStats.crunched_at: now}, synchronize_session=False
                )
                session.commit()
            except Exception as e:
                # Leave crunched_at alone so this IP is retried next run.
                session.rollback()
                app_logger.error(f"crunch-access-logs: {ip} failed: {e}")
                continue
            ips_done += 1
            groups_merged += merged
            rows_deleted += deleted
        if groups_merged:
            invalidate_table_cache()
            app_logger.info(
                f"crunch-access-logs: {ips_done} IPs, {groups_merged} groups merged, "
                f"{rows_deleted} rows deleted"
            )
    finally:
        db.close_session()
