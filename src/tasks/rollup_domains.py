#!/usr/bin/env python3

"""Keep per-day Targeted Domains totals in Redis.

Targeted Domains and the domain map sum these instead of grouping the whole
access log (60s+ on 10M rows). Each day maps evidence ("1": suspicious or
honeypot, kept longer by retention) and plain ("0") traffic to
{host: [hits, distinct IPs, first_seen, last_seen]}; "0" counts only IPs with
no evidence row that day, so the two add up. Days are rebuilt whole, so runs
are idempotent: missing days, today, yesterday, and days retention splits or
has yet to trim. Standalone mode has no Redis and reads the log live.
"""

import json
from datetime import date, datetime, time, timedelta

from sqlalchemy import distinct, func, or_, select

from dashboard_cache import get_backend, get_redis_client
from database import get_database
from database.access_logs import DOMAIN_DAILY_KEY
from logger import get_app_logger
from models import AccessLog

app_logger = get_app_logger()

TASK_CONFIG = {
    "name": "rollup-domains",
    "cron": "23 * * * *",
    "enabled": True,
    # A fresh install would otherwise read the log live for up to an hour.
    "run_when_loaded": True,
    "single_pod": True,
}

DAY = timedelta(days=1)
_EVIDENCE = or_(
    AccessLog.is_suspicious.is_(True), AccessLog.is_honeypot_trigger.is_(True)
)


def _day(session, day: date) -> dict:
    """Both kinds of one day's per-host totals, in one pass over the log."""
    ts = AccessLog.timestamp
    start = datetime.combine(day, time.min)
    ip = distinct(AccessLog.ip)
    cols = [
        agg.filter(kind)
        for kind in (_EVIDENCE, ~_EVIDENCE)
        for agg in (func.count(), func.count(ip), func.min(ts), func.max(ts))
    ]
    out = {"1": {}, "0": {}}
    for host, all_ips, *aggs in session.execute(
        select(AccessLog.target_host, func.count(ip), *cols)
        .where(
            AccessLog.target_host.isnot(None),
            AccessLog.target_host != "",
            ts >= start,
            ts < start + DAY,
        )
        .group_by(AccessLog.target_host)
    ):
        ev_ips = aggs[1] or 0
        for kind, (h, ips, first, last) in zip(out, (aggs[:4], aggs[4:]), strict=True):
            if h:
                # Plain counts only IPs with no evidence row, so the kinds add up.
                n = ips if kind == "1" else all_ips - ev_ips
                out[kind][host] = [int(h), n, str(first), str(last)]
    return out


def refresh(session, days: dict, now: datetime, retention: timedelta) -> dict:
    """Rebuild stale days in place; drop days the log no longer reaches."""
    first = session.scalar(select(func.min(AccessLog.timestamp)))
    if first is None:
        return {}
    first, today = first.date(), now.date()
    cut = (now - retention).date()
    # Today; yesterday while late rows land; days retention splits or has
    # yet to reach (plain rows still counted).
    stale = {today, first, cut}
    if now - datetime.combine(today, time.min) < timedelta(hours=2):
        stale.add(today - DAY)
    stale |= {
        date.fromisoformat(k)
        for k, v in days.items()
        if k < cut.isoformat() and v.get("0")
    }
    for k in [k for k in days if k < first.isoformat()]:
        del days[k]
    d = first
    while d <= today:
        if d.isoformat() not in days or d in stale:
            days[d.isoformat()] = _day(session, d)
        d += DAY
    return days


def main():
    from config import get_config

    client = get_redis_client()
    if get_backend() != "scalable" or client is None:
        return
    db = get_database()
    session = db.session
    try:
        config = get_config()
        raw = client.get(DOMAIN_DAILY_KEY)
        days = refresh(
            session,
            json.loads(raw) if raw else {},
            datetime.now(),
            config.retention_non_suspicious,
        )
        client.set(DOMAIN_DAILY_KEY, json.dumps(days))
        app_logger.info(f"[Background Task] rollup-domains: {len(days)} days")
    except Exception as e:
        app_logger.error(f"[Background Task] rollup-domains failed: {e}")
    finally:
        db.close_session()
