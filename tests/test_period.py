"""Period window helper: days/offset/slot -> UTC window and bucket labels."""

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from period import bucket_hours, period_query, resolve_period, slot_labels  # noqa: E402

NOW = datetime(2026, 10, 30, 11, 30)


def test_none_days_means_all_time():
    assert resolve_period(None) is None


def test_bucket_sizes():
    assert [bucket_hours(d) for d in (1, 7, 30)] == [1, 4, 24]


def test_window_is_utc_and_offset():
    p = resolve_period(7, offset_days=7, now=NOW)
    assert p.until == NOW - timedelta(days=7)
    assert p.since == NOW - timedelta(days=14)


def test_slot_narrows_to_one_bucket():
    p = resolve_period(7, slot="2026-10-27T04", now=NOW)
    assert (p.since, p.until) == (datetime(2026, 10, 27, 4), datetime(2026, 10, 27, 8))
    assert p.slot == "2026-10-27T04"


@pytest.mark.parametrize("bad", ["", "2026-10-27", "x", "2020-01-01T00", "2026-10-27T99"])
def test_bad_or_out_of_period_slot_is_ignored(bad):
    p = resolve_period(7, slot=bad, now=NOW)
    assert p.slot is None and p.since == NOW - timedelta(days=7)


def test_unaligned_slot_is_ignored():
    p = resolve_period(7, slot="2026-10-27T05", now=NOW)
    assert p.slot is None and p.since == NOW - timedelta(days=7)


def test_clamps():
    p = resolve_period(500, offset_days=-3, now=NOW)
    assert (p.days, p.offset_days) == (90, 0)


def test_slot_labels_align_to_buckets():
    labels = slot_labels(resolve_period(1, now=NOW))
    assert labels[-1] == "2026-10-30T11" and len(labels) == 25
    assert all(int(l[-2:]) % 4 == 0 for l in slot_labels(resolve_period(7, now=NOW)))


def test_period_query():
    assert period_query(None) == ""
    assert period_query(resolve_period(7, slot="2026-10-27T04", now=NOW)) == "&days=7&offset_days=0&slot=2026-10-27T04"
