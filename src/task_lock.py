#!/usr/bin/env python3

"""Cross-pod lease for work that must happen once per cluster, not once per pod.

Scalable mode runs N pods, each with its own BackgroundScheduler, so anything
with a global effect -- a backup, a retention sweep, a third-party API call --
happens N times unless one pod claims it first. This is that claim.

Keys live under krawl:task:, deliberately outside krawl:cache:. Cache entries
are disposable and short-TTL'd; a lease is neither, and mixing the two invites
exactly the kind of bulk delete that would release every lock in the cluster at
once. krawl:counter: draws the same line for the same reason.

Every function fails open: standalone mode and an unreachable Redis both grant
the claim. A honeypot that silently stops doing maintenance is worse than one
that does it twice.
"""

import datetime
import json
import os
import threading
import time
import uuid

from dashboard_cache import get_backend, get_redis_client

LOCK_PREFIX: str = "krawl:task:lock:"

# Reserved for the work-sharding scheme that issue #296 defers. Nothing reads or
# writes it yet; it is declared so the namespace is not taken by something else.
QUEUE_PREFIX: str = "krawl:task:queue:"

# Stored as the lease value so `redis-cli get` names the holder. HOSTNAME is the
# pod name under Kubernetes; the uuid covers bare docker and local runs.
POD_UID: str = os.environ.get("HOSTNAME") or f"pod-{uuid.uuid4().hex[:8]}"

# Standalone has no Redis, but the maintenance panel still needs two concurrent
# clicks to be rejected. Mirrors the process-local fallback in auth_store.
_local_leases: dict[str, float] = {}
_local_lock = threading.Lock()


def _local_claim(job_id: str, lease_seconds: int) -> bool:
    """Claim against the process-local lease table used in standalone mode."""
    now = time.time()
    with _local_lock:
        expires = _local_leases.get(job_id)
        if expires is not None and expires > now:
            return False
        _local_leases[job_id] = now + lease_seconds
        return True


def claim(job_id: str, lease_seconds: int) -> bool:
    """Claim the right to run `job_id` for the next `lease_seconds`.

    Returns True for exactly one pod per lease window in scalable mode, and for
    the single process in standalone mode.

    The lease is deliberately NOT released when the work finishes; callers let
    it expire. TasksMaster schedules every job with up to TASK_JITTER seconds of
    jitter, so releasing on completion would simply hand the same occurrence to
    the next pod to fire. The lease is the "this occurrence already ran" marker,
    not a mutex. See TasksMaster._lease_seconds.
    """
    if get_backend() != "scalable":
        return _local_claim(job_id, lease_seconds)

    redis_client = get_redis_client()
    if redis_client is None:
        return True

    return bool(
        redis_client.set(f"{LOCK_PREFIX}{job_id}", POD_UID, nx=True, ex=lease_seconds)
    )


def release(job_id: str) -> None:
    """Drop a lease early, for callers that want a mutex rather than a lease.

    The scheduler never calls this. The maintenance panel does: a task run by
    hand should be runnable again the moment it finishes.
    """
    if get_backend() != "scalable":
        with _local_lock:
            _local_leases.pop(job_id, None)
        return

    redis_client = get_redis_client()
    if redis_client is not None:
        redis_client.delete(f"{LOCK_PREFIX}{job_id}")


def is_held(job_id: str) -> bool:
    """True while someone holds the lease.

    Advisory only -- the lease can expire between this check and its use. Callers
    that need the answer to be binding should use claim() instead.
    """
    if get_backend() != "scalable":
        with _local_lock:
            expires = _local_leases.get(job_id)
            return expires is not None and expires > time.time()

    redis_client = get_redis_client()
    if redis_client is None:
        return False
    return bool(redis_client.exists(f"{LOCK_PREFIX}{job_id}"))


LAST_RUN_PREFIX: str = "krawl:task:last_run:"

# Long enough that a task on a weekly-ish schedule still shows its last run, and
# short enough that a task deleted from the folder stops appearing eventually.
LAST_RUN_TTL: int = 14 * 24 * 3600

# Standalone has no Redis; the panel still wants to show the last run.
_local_last_runs: dict[str, str] = {}


def record_run(task_name: str, ok: bool) -> None:
    """Record that this pod just ran `task_name`, successfully or not.

    Deliberately separate from the lease. A lease is held for twice the jitter
    window and then expires -- a daily task holds one for 480 seconds out of
    86400 -- so it cannot answer "who ran this", only "who is mid-window right
    now". The dashboard needs the durable answer.
    """
    payload = json.dumps(
        {
            "pod": POD_UID,
            "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "ok": bool(ok),
        }
    )

    if get_backend() != "scalable":
        with _local_lock:
            _local_last_runs[task_name] = payload
        return

    redis_client = get_redis_client()
    if redis_client is not None:
        redis_client.setex(f"{LAST_RUN_PREFIX}{task_name}", LAST_RUN_TTL, payload)


def get_last_run(task_name: str) -> dict | None:
    """The last recorded run of `task_name`, or None if it has not run.

    Returns {"pod": str, "at": ISO-8601 str, "ok": bool}.
    """
    if get_backend() != "scalable":
        with _local_lock:
            payload = _local_last_runs.get(task_name)
    else:
        redis_client = get_redis_client()
        payload = (
            redis_client.get(f"{LAST_RUN_PREFIX}{task_name}")
            if redis_client is not None
            else None
        )

    if not payload:
        return None
    return json.loads(payload)
