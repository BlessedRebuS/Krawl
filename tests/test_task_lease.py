#!/usr/bin/env python3

"""Lease length must outlast the scheduler's jitter but expire before the next run.

TasksMaster gives every job up to TASK_JITTER seconds of jitter, so two pods fire
the same cron minutes apart. A lease shorter than that window is already expired
when the late pod fires, and the occurrence runs twice. A lease longer than the
period blocks the following occurrence.

Usage: python tests/test_task_lease.py
"""

import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

import dashboard_cache
from tasks_master import TasksMaster

JITTER = TasksMaster.TASK_JITTER


def test_trigger_period_for_cron():
    assert TasksMaster._trigger_period(CronTrigger.from_crontab("0 9 * * *")) == 86400
    assert TasksMaster._trigger_period(CronTrigger.from_crontab("*/1 * * * *")) == 60
    assert TasksMaster._trigger_period(CronTrigger.from_crontab("*/5 * * * *")) == 300


def test_trigger_period_for_interval():
    assert TasksMaster._trigger_period(IntervalTrigger(seconds=30)) == 30
    assert TasksMaster._trigger_period(IntervalTrigger(seconds=3600)) == 3600


def test_lease_covers_jitter_without_blocking_the_next_run():
    for crontab in ("0 9 * * *", "*/15 * * * *", "*/5 * * * *"):
        trigger = CronTrigger.from_crontab(crontab)
        period = TasksMaster._trigger_period(trigger)
        lease = TasksMaster._lease_seconds(trigger)
        assert lease < period, f"{crontab}: lease {lease} would block the next run"
        assert lease >= JITTER, f"{crontab}: lease {lease} does not cover {JITTER}s jitter"


def test_short_period_lease_stays_below_the_period():
    """Sub-jitter periods cannot cover the jitter window; they must still not block."""
    for seconds in (30, 60):
        trigger = IntervalTrigger(seconds=seconds)
        lease = TasksMaster._lease_seconds(trigger)
        assert 0 < lease < seconds, f"{seconds}s interval got lease {lease}"


def test_daily_lease_is_not_a_day_long():
    """A crashed leader must not leave a 24-hour tombstone."""
    lease = TasksMaster._lease_seconds(CronTrigger.from_crontab("0 9 * * *"))
    assert lease <= 2 * JITTER, f"daily lease {lease} is longer than it needs to be"


def _fake_module(with_on_skip: bool):
    module = types.ModuleType("fake_task")
    module.calls = []
    module.main = lambda: module.calls.append("main")
    if with_on_skip:
        module.on_skip = lambda: module.calls.append("on_skip")
    return module


class _FakeRedis:
    def __init__(self):
        self.store = {}

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True


def test_guard_runs_the_leader_and_skips_the_rest():
    dashboard_cache._backend = "scalable"
    dashboard_cache._redis_client = _FakeRedis()

    module = _fake_module(with_on_skip=False)
    guarded = TasksMaster._guarded(module.main, module, "fake-job", 60)

    guarded()
    guarded()
    assert module.calls == ["main"], f"expected one run, got {module.calls}"


def test_guard_calls_on_skip_when_the_claim_is_lost():
    dashboard_cache._backend = "scalable"
    dashboard_cache._redis_client = _FakeRedis()

    module = _fake_module(with_on_skip=True)
    guarded = TasksMaster._guarded(module.main, module, "fake-job-2", 60)

    guarded()
    guarded()
    assert module.calls == ["main", "on_skip"], f"got {module.calls}"


if __name__ == "__main__":
    test_trigger_period_for_cron()
    test_trigger_period_for_interval()
    test_lease_covers_jitter_without_blocking_the_next_run()
    test_short_period_lease_stays_below_the_period()
    test_daily_lease_is_not_a_day_long()
    test_guard_runs_the_leader_and_skips_the_rest()
    test_guard_calls_on_skip_when_the_claim_is_lost()
    print("PASS: task lease and guard")
