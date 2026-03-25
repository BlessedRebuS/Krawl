"""
Cache layer for dashboard Overview data.

Supports two backends based on deployment mode:
- standalone: in-memory dict with threading lock (default)
- scalable: Redis with key prefix and TTL

A background task periodically refreshes this cache so the dashboard
serves pre-computed data instantly instead of hitting the database cold.

Memory footprint is fixed — each key is overwritten on every refresh.
"""

import json
import threading
from datetime import datetime
from typing import Any, Optional

_backend: str = "standalone"
_lock = threading.Lock()
_cache: dict[str, Any] = {}
_redis_client = None
_REDIS_PREFIX = "krawl:cache:"
_REDIS_TTL = 600  # 10 minutes


def _json_serializer(obj):
    """Handle non-serializable types for Redis JSON encoding."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def initialize_cache(mode: str = "standalone", redis_config: dict = None) -> None:
    """
    Initialize the cache backend.

    Args:
        mode: "standalone" for in-memory dict, "scalable" for Redis
        redis_config: Redis connection settings (host, port, db, password)
    """
    global _backend, _redis_client
    _backend = mode

    if mode == "scalable":
        import redis

        redis_config = redis_config or {}
        _redis_client = redis.Redis(
            host=redis_config.get("host", "localhost"),
            port=redis_config.get("port", 6379),
            db=redis_config.get("db", 0),
            password=redis_config.get("password"),
            decode_responses=True,
            retry_on_timeout=True,
            socket_connect_timeout=5,
        )
        # Verify connection
        _redis_client.ping()


def get_cached(key: str) -> Optional[Any]:
    """Get a value from the dashboard cache."""
    if _backend == "scalable" and _redis_client is not None:
        raw = _redis_client.get(f"{_REDIS_PREFIX}{key}")
        return json.loads(raw) if raw else None

    with _lock:
        return _cache.get(key)


def set_cached(key: str, value: Any) -> None:
    """Set a value in the dashboard cache."""
    if _backend == "scalable" and _redis_client is not None:
        _redis_client.setex(
            f"{_REDIS_PREFIX}{key}",
            _REDIS_TTL,
            json.dumps(value, default=_json_serializer),
        )
        return

    with _lock:
        _cache[key] = value


def is_warm() -> bool:
    """Check if the cache has been populated at least once."""
    if _backend == "scalable" and _redis_client is not None:
        return _redis_client.exists(f"{_REDIS_PREFIX}stats") > 0

    with _lock:
        return "stats" in _cache
