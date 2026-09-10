#!/usr/bin/env python3

"""The dashboard needs a durable record of which pod last ran each task.

The lease itself cannot answer this: a daily task holds it for 480 seconds out
of 86400, so a panel reading the lock would be blank 99% of the time.

Usage: python tests/test_task_last_run.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import dashboard_cache


class FakeRedis:
    def __init__(self):
        self.store = {}

    def setex(self, key, ttl, value):
        self.store[key] = value
        return True

    def get(self, key):
        return self.store.get(key)


def use_scalable():
    dashboard_cache._backend = "scalable"
    dashboard_cache._redis_client = FakeRedis()


def test_record_then_read_round_trips():
    use_scalable()
    import task_lock

    task_lock.record_run("db-retention", ok=True)
    entry = task_lock.get_last_run("db-retention")

    assert entry is not None, "a recorded run must be readable"
    assert entry["pod"] == task_lock.POD_UID
    assert entry["ok"] is True
    assert entry["at"], "the record must carry a timestamp"


def test_failure_is_recorded_as_such():
    use_scalable()
    import task_lock

    task_lock.record_run("db-dump", ok=False)
    assert task_lock.get_last_run("db-dump")["ok"] is False


def test_unrun_task_has_no_record():
    use_scalable()
    import task_lock

    assert task_lock.get_last_run("never-ran") is None


def test_record_works_in_standalone():
    dashboard_cache._backend = "standalone"
    dashboard_cache._redis_client = None
    import task_lock

    task_lock.record_run("db-dump", ok=True)
    entry = task_lock.get_last_run("db-dump")
    assert entry is not None and entry["pod"] == task_lock.POD_UID


def test_record_keys_stay_out_of_the_cache_namespace():
    use_scalable()
    import task_lock

    task_lock.record_run("db-dump", ok=True)
    assert task_lock.LAST_RUN_PREFIX == "krawl:task:last_run:"
    for key in dashboard_cache._redis_client.store:
        assert not key.startswith("krawl:cache:"), f"{key} belongs to the disposable cache"


def test_job_listener_records_the_run():
    """job_listener already sees every completion; it is where the record belongs."""
    use_scalable()
    import task_lock
    from apscheduler.schedulers.background import BackgroundScheduler
    from tasks_master import TasksMaster

    master = TasksMaster(BackgroundScheduler())

    class FakeEvent:
        job_id = "db_retention__db-retention"
        exception = None

    master.job_listener(FakeEvent())
    entry = task_lock.get_last_run("db-retention")
    assert entry is not None, "job_listener must record the run"
    assert entry["ok"] is True

    class FakeFailure:
        job_id = "db_dump__dump-krawl-data"
        exception = RuntimeError("boom")

    master.job_listener(FakeFailure())
    assert task_lock.get_last_run("dump-krawl-data")["ok"] is False


if __name__ == "__main__":
    test_record_then_read_round_trips()
    test_failure_is_recorded_as_such()
    test_unrun_task_has_no_record()
    test_record_works_in_standalone()
    test_record_keys_stay_out_of_the_cache_namespace()
    test_job_listener_records_the_run()
    print("PASS: task last-run record")
