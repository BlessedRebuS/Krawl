#!/usr/bin/env python3

"""The cross-pod lease must hand a job to exactly one pod per window.

Usage: python tests/test_task_lock.py
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import dashboard_cache


class FakeRedis:
    """Only the calls task_lock makes, with real NX and EX semantics."""

    def __init__(self):
        self.store: dict[str, tuple[str, float | None]] = {}

    def _alive(self, key: str) -> bool:
        entry = self.store.get(key)
        if entry is None:
            return False
        expires = entry[1]
        if expires is not None and expires <= time.time():
            del self.store[key]
            return False
        return True

    def set(self, key, value, nx=False, ex=None):
        if nx and self._alive(key):
            return None
        self.store[key] = (value, time.time() + ex if ex else None)
        return True

    def delete(self, key):
        self.store.pop(key, None)

    def exists(self, key):
        return 1 if self._alive(key) else 0


def use_scalable(redis_client) -> None:
    """Point the cache module at a fake Redis, as scalable mode would."""
    dashboard_cache._backend = "scalable"
    dashboard_cache._redis_client = redis_client


def use_standalone() -> None:
    dashboard_cache._backend = "standalone"
    dashboard_cache._redis_client = None


def test_one_pod_wins():
    use_scalable(FakeRedis())
    import task_lock

    first = task_lock.claim("db-retention", 60)
    second = task_lock.claim("db-retention", 60)
    assert first is True, "the first pod must win the claim"
    assert second is False, f"a second pod must lose it, got {second}"


def test_different_jobs_do_not_collide():
    use_scalable(FakeRedis())
    import task_lock

    assert task_lock.claim("db-retention", 60) is True
    assert task_lock.claim("db-dump", 60) is True, "distinct jobs share no lease"


def test_lease_expiry_frees_the_job():
    use_scalable(FakeRedis())
    import task_lock

    assert task_lock.claim("db-dump", 1) is True
    assert task_lock.claim("db-dump", 1) is False
    time.sleep(1.1)
    assert task_lock.claim("db-dump", 1) is True, "an expired lease must be reclaimable"


def test_standalone_always_claims():
    """One process, so a released job must be immediately reclaimable."""
    use_standalone()
    import task_lock

    task_lock._local_leases.clear()
    assert task_lock.claim("db-dump", 60) is True
    task_lock.release("db-dump")
    assert task_lock.claim("db-dump", 60) is True, "standalone must never stay gated"


def test_standalone_still_rejects_a_concurrent_run():
    """The maintenance panel needs a second click rejected even without Redis."""
    use_standalone()
    import task_lock

    task_lock._local_leases.clear()
    assert task_lock.claim("manual", 60) is True
    assert task_lock.claim("manual", 60) is False


def test_missing_redis_fails_open():
    dashboard_cache._backend = "scalable"
    dashboard_cache._redis_client = None
    import task_lock

    assert task_lock.claim("db-dump", 60) is True, "no Redis must not stop maintenance"


def test_release_frees_the_job():
    use_scalable(FakeRedis())
    import task_lock

    assert task_lock.claim("manual-run", 3600) is True
    assert task_lock.is_held("manual-run") is True
    task_lock.release("manual-run")
    assert task_lock.is_held("manual-run") is False
    assert task_lock.claim("manual-run", 3600) is True


def test_lock_keys_stay_out_of_the_cache_namespace():
    """krawl:cache:* is disposable and TTL'd; a lease is neither."""
    redis_client = FakeRedis()
    use_scalable(redis_client)
    import task_lock

    task_lock.claim("db-dump", 60)
    assert task_lock.LOCK_PREFIX == "krawl:task:lock:"
    for key in redis_client.store:
        assert not key.startswith("krawl:cache:"), f"{key} belongs to the disposable cache"


def test_holder_is_recorded():
    """A held lease names its holder, so redis-cli shows which pod has it."""
    redis_client = FakeRedis()
    use_scalable(redis_client)
    import task_lock

    task_lock.claim("db-dump", 60)
    value, _ = redis_client.store[f"{task_lock.LOCK_PREFIX}db-dump"]
    assert value == task_lock.POD_UID, f"expected {task_lock.POD_UID}, got {value}"


if __name__ == "__main__":
    test_one_pod_wins()
    test_different_jobs_do_not_collide()
    test_lease_expiry_frees_the_job()
    test_standalone_always_claims()
    test_standalone_still_rejects_a_concurrent_run()
    test_missing_redis_fails_open()
    test_release_frees_the_job()
    test_lock_keys_stay_out_of_the_cache_namespace()
    test_holder_is_recorded()
    print("PASS: task_lock")
