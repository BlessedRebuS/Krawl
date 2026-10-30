"""Shared UTC period window (days, offset, optional bucket slot) for the Attacks tab."""

from dataclasses import dataclass
from datetime import datetime, timedelta

SLOT_FMT = "%Y-%m-%dT%H"


def bucket_hours(days: int) -> int:
    return 1 if days == 1 else 4 if days <= 7 else 24


@dataclass(frozen=True)
class Period:
    since: datetime
    until: datetime
    days: int
    offset_days: int
    bucket_hours: int
    slot: str | None


def parse_slot(slot: str | None) -> datetime | None:
    try:
        return datetime.strptime(slot, SLOT_FMT)
    except (TypeError, ValueError):
        return None


def resolve_period(days, offset_days=0, slot=None, now=None) -> Period | None:
    if days is None:
        return None
    days = max(1, min(90, int(days)))
    offset_days = max(0, int(offset_days))
    bh = bucket_hours(days)
    until = (now or datetime.utcnow()) - timedelta(days=offset_days)
    since = until - timedelta(days=days)
    start = parse_slot(slot)
    if start is not None and start.hour % bh == 0:
        end = start + timedelta(hours=bh)
        if end > since and start < until:
            since, until = max(since, start), min(until, end)
            return Period(since, until, days, offset_days, bh, slot)
    return Period(since, until, days, offset_days, bh, None)


def slot_labels(period: Period) -> list[str]:
    cur = period.since.replace(minute=0, second=0, microsecond=0)
    cur -= timedelta(hours=cur.hour % period.bucket_hours)
    labels = []
    while cur < period.until:
        labels.append(cur.strftime(SLOT_FMT))
        cur += timedelta(hours=period.bucket_hours)
    return labels


def period_query(period: Period | None) -> str:
    if period is None:
        return ""
    q = f"&days={period.days}&offset_days={period.offset_days}"
    return q + f"&slot={period.slot}" if period.slot else q
