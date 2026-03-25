"""
Cache layer for dashboard and hot-path data.

Supports two backends based on deployment mode:
- standalone: in-memory dict with threading lock (default)
- scalable: Redis with key prefix and TTL

A background task periodically refreshes this cache so the dashboard
serves pre-computed data instantly instead of hitting the database cold.

In scalable mode, Redis is also used for:
- Hot-path caching (ban info, IP categories) with short TTLs
- Dashboard table caching (attackers, credentials, honeypot, etc.)
- Attack pattern statistics

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
_REDIS_TTL = 600  # default: 10 minutes for dashboard warmup data
_REDIS_SHORT_TTL = 30  # default: 30 seconds for hot-path data (ban info, IP categories)
_REDIS_TABLE_TTL = 120  # default: 2 minutes for paginated dashboard tables


def _json_serializer(obj):
    """Handle non-serializable types for Redis JSON encoding."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def initialize_cache(
    mode: str = "standalone", redis_config: dict = None, ttl_config: dict = None
) -> None:
    """
    Initialize the cache backend.

    Args:
        mode: "standalone" for in-memory dict, "scalable" for Redis
        redis_config: Redis connection settings (host, port, db, password)
        ttl_config: Optional TTL overrides (cache_ttl, hot_ttl, table_ttl)
    """
    global _backend, _redis_client, _REDIS_TTL, _REDIS_SHORT_TTL, _REDIS_TABLE_TTL
    _backend = mode

    if ttl_config:
        _REDIS_TTL = ttl_config.get("cache_ttl", _REDIS_TTL)
        _REDIS_SHORT_TTL = ttl_config.get("hot_ttl", _REDIS_SHORT_TTL)
        _REDIS_TABLE_TTL = ttl_config.get("table_ttl", _REDIS_TABLE_TTL)

    if mode == "scalable":
        import redis

        redis_config = redis_config or {}
        _redis_client = redis.Redis(
            host=redis_config.get("host", "localhost"),
            port=redis_config.get("port", 6379),
            db=redis_config.get("db", 0),
            password=redis_config.get("password") or None,
            decode_responses=True,
            retry_on_timeout=True,
            socket_connect_timeout=5,
        )
        # Verify connection
        _redis_client.ping()


def get_redis_client():
    """Get the Redis client instance (for use in scalable mode only)."""
    return _redis_client


def get_backend() -> str:
    """Get the current cache backend mode."""
    return _backend


def get_cached(key: str) -> Optional[Any]:
    """Get a value from the dashboard cache."""
    if _backend == "scalable" and _redis_client is not None:
        raw = _redis_client.get(f"{_REDIS_PREFIX}{key}")
        return json.loads(raw) if raw else None

    with _lock:
        return _cache.get(key)


def set_cached(key: str, value: Any, ttl: int = None) -> None:
    """Set a value in the dashboard cache.

    Args:
        key: Cache key
        value: Value to cache (must be JSON-serializable for Redis)
        ttl: Optional TTL override in seconds (Redis only, defaults to _REDIS_TTL)
    """
    if _backend == "scalable" and _redis_client is not None:
        _redis_client.setex(
            f"{_REDIS_PREFIX}{key}",
            ttl or _REDIS_TTL,
            json.dumps(value, default=_json_serializer),
        )
        return

    with _lock:
        _cache[key] = value


def get_cached_short(key: str) -> Optional[Any]:
    """Get a value from the short-TTL hot-path cache (scalable mode only).

    In standalone mode, always returns None (no hot-path caching needed
    since there's only one process and DB is local).
    """
    if _backend == "scalable" and _redis_client is not None:
        raw = _redis_client.get(f"{_REDIS_PREFIX}hot:{key}")
        return json.loads(raw) if raw else None
    return None


def set_cached_short(key: str, value: Any, ttl: int = None) -> None:
    """Set a value in the short-TTL hot-path cache (scalable mode only).

    Uses a short TTL (default 30s) for data that changes frequently but is
    expensive to query on every request (ban info, IP categories).
    In standalone mode, this is a no-op.

    Args:
        key: Cache key
        value: Value to cache
        ttl: Optional TTL override in seconds (defaults to _REDIS_SHORT_TTL)
    """
    if _backend == "scalable" and _redis_client is not None:
        _redis_client.setex(
            f"{_REDIS_PREFIX}hot:{key}",
            ttl or _REDIS_SHORT_TTL,
            json.dumps(value, default=_json_serializer),
        )


def delete_cached_short(key: str) -> None:
    """Delete a hot-path cache entry (scalable mode only).

    Used to immediately invalidate cached ban info or IP stats
    when the underlying data changes.
    In standalone mode, this is a no-op.
    """
    if _backend == "scalable" and _redis_client is not None:
        _redis_client.delete(f"{_REDIS_PREFIX}hot:{key}")


def get_cached_table(key: str) -> Optional[Any]:
    """Get a cached paginated table result (scalable mode only).

    In standalone mode, always returns None (tables are served live
    or from the warmup cache).
    """
    if _backend == "scalable" and _redis_client is not None:
        raw = _redis_client.get(f"{_REDIS_PREFIX}table:{key}")
        return json.loads(raw) if raw else None
    return None


def set_cached_table(key: str, value: Any) -> None:
    """Cache a paginated table result with medium TTL (scalable mode only).

    Uses a 2-minute TTL for dashboard table data that doesn't need to be
    real-time but benefits from caching across multiple replicas.
    In standalone mode, this is a no-op.
    """
    if _backend == "scalable" and _redis_client is not None:
        _redis_client.setex(
            f"{_REDIS_PREFIX}table:{key}",
            _REDIS_TABLE_TTL,
            json.dumps(value, default=_json_serializer),
        )


def invalidate_table_cache() -> None:
    """Invalidate all cached table data (e.g. after a write operation).

    Useful after ban overrides, IP tracking changes, etc.
    In standalone mode, this is a no-op.
    """
    if _backend == "scalable" and _redis_client is not None:
        cursor = 0
        while True:
            cursor, keys = _redis_client.scan(
                cursor, match=f"{_REDIS_PREFIX}table:*", count=100
            )
            if keys:
                _redis_client.delete(*keys)
            if cursor == 0:
                break


def is_warm() -> bool:
    """Check if the cache has been populated at least once."""
    if _backend == "scalable" and _redis_client is not None:
        return _redis_client.exists(f"{_REDIS_PREFIX}stats") > 0

    with _lock:
        return "stats" in _cache
