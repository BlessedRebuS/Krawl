"""
In-memory cache for dashboard Overview data.

A background task periodically refreshes this cache so the dashboard
serves pre-computed data instantly instead of hitting SQLite cold.

Memory footprint is fixed — each key is overwritten on every refresh.
"""

import threading
from typing import Any, Dict, Optional

_lock = threading.Lock()
_cache: Dict[str, Any] = {}


def get_cached(key: str) -> Optional[Any]:
    """Get a value from the dashboard cache."""
    with _lock:
        return _cache.get(key)


def set_cached(key: str, value: Any) -> None:
    """Set a value in the dashboard cache."""
    with _lock:
        _cache[key] = value


def is_warm() -> bool:
    """Check if the cache has been populated at least once."""
    with _lock:
        return "stats" in _cache
