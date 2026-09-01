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
from typing import Any

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


def get_cached(key: str) -> Any | None:
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


# Items pushed per RPUSH when storing a cached list, so a 100k-row aggregate
# does not become one enormous command.
_LIST_PUSH_BATCH = 1_000


def set_cached_list(key: str, items: list, ttl: int = None) -> None:
    """Cache a pre-sorted list so pages can be served without reading it whole.

    In scalable mode the list is stored as a Redis LIST of per-item JSON rather
    than one JSON blob, which is what lets get_cached_list_page() fetch a
    ten-row slice with LRANGE. The blob form meant every request for any page
    transferred and parsed the entire aggregate — tens of MB, for ten rows.

    Standalone keeps the plain in-memory list: there is no serialization
    boundary to cross, so slicing it directly is already optimal.
    """
    if _backend == "scalable" and _redis_client is not None:
        redis_key = f"{_REDIS_PREFIX}list:{key}"
        encoded = [json.dumps(i, default=_json_serializer) for i in items]
        pipe = _redis_client.pipeline()
        # Build under a temporary key and rename into place, so readers never
        # observe a half-populated list mid-refresh.
        staging = f"{redis_key}:staging"
        pipe.delete(staging)
        for start in range(0, len(encoded), _LIST_PUSH_BATCH):
            pipe.rpush(staging, *encoded[start : start + _LIST_PUSH_BATCH])
        if encoded:
            pipe.rename(staging, redis_key)
            pipe.expire(redis_key, ttl or _REDIS_TTL)
        else:
            pipe.delete(redis_key)
        pipe.execute()
        return

    with _lock:
        _cache[f"list:{key}"] = list(items)


def get_cached_list_page(key: str, page: int, page_size: int) -> dict | None:
    """Return one page of a cached list, or None if the list is not cached.

    The shape matches paginate_cached_list() so callers are interchangeable.
    """
    if _backend == "scalable" and _redis_client is not None:
        redis_key = f"{_REDIS_PREFIX}list:{key}"
        total = _redis_client.llen(redis_key)
        if not total:
            return None
        total_pages = max(1, (total + page_size - 1) // page_size)
        page = max(1, min(page, total_pages))
        offset = (page - 1) * page_size
        # LRANGE is inclusive on both ends.
        raw = _redis_client.lrange(redis_key, offset, offset + page_size - 1)
        return {
            "items": [json.loads(r) for r in raw],
            "pagination": pagination(page, page_size, total),
        }

    with _lock:
        items = _cache.get(f"list:{key}")
    if items is None:
        return None
    return paginate_cached_list(items, page, page_size)


def get_cached_short(key: str) -> Any | None:
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


def get_cached_table(key: str) -> Any | None:
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


def flush_all() -> None:
    """Flush all Krawl cache keys.

    In scalable mode, deletes all Redis keys with the krawl:cache: prefix.
    In standalone mode, clears the in-memory dict.
    Called on startup so each pod restart begins with a fresh cache.
    """
    if _backend == "scalable" and _redis_client is not None:
        cursor = 0
        while True:
            cursor, keys = _redis_client.scan(
                cursor, match=f"{_REDIS_PREFIX}*", count=200
            )
            if keys:
                _redis_client.delete(*keys)
            if cursor == 0:
                break
        return

    with _lock:
        _cache.clear()


def pagination(page: int, page_size: int, total: int) -> dict:
    """Build the pagination block shared by every paginated response.

    total_pages is at least 1 so an empty table still reads "page 1 of 1".
    """
    return {
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": max(1, (total + page_size - 1) // page_size),
    }


def paginate_cached_list(items: list, page: int, page_size: int) -> dict:
    """Slice a pre-computed sorted list into a paginated response."""
    total = len(items)
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = max(1, min(page, total_pages))
    offset = (page - 1) * page_size
    return {
        "items": items[offset : offset + page_size],
        "pagination": pagination(page, page_size, total),
    }


def is_warm() -> bool:
    """Check if the cache has been populated at least once."""
    if _backend == "scalable" and _redis_client is not None:
        return _redis_client.exists(f"{_REDIS_PREFIX}stats") > 0

    with _lock:
        return "stats" in _cache
