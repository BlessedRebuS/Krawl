import threading
import time

import requests

from logger import get_app_logger

# Frozen and swapped wholesale: the ban-check middleware reads this on every
# request, and copying a 100k-entry set per request cost ~4 MiB each time.
_global_banlist: frozenset[str] = frozenset()
_banlist_sources: list[dict] = []
_last_refresh: float = 0.0
_lock = threading.Lock()


def get_global_banlist() -> frozenset[str]:
    """Return the current in-memory global banlist (IPs from all sources).

    The returned set is immutable and shared — do not copy it on hot paths.
    """
    return _global_banlist


def is_globally_banned(ip: str) -> bool:
    """Membership test against the global banlist, without copying it."""
    return ip in _global_banlist


def get_banlist_sources() -> list[dict]:
    """Return list of sources with their status for dashboard display."""
    with _lock:
        return list(_banlist_sources)


def refresh_banlist_sources(*, source_urls: list[str] | None = None) -> None:
    """Fetch all configured banlist sources and merge IPs into the global set.

    Called on startup and periodically by the refresh_banlist task.
    """
    global _global_banlist, _last_refresh

    from config import get_config

    config = get_config()
    urls = source_urls if source_urls is not None else (config.banlist_sources or [])

    if not urls:
        with _lock:
            _global_banlist = frozenset()
            _banlist_sources.clear()
            _last_refresh = time.time()
        return

    combined: set[str] = set()
    sources_info: list[dict] = []

    for url in urls:
        entry: dict = {"url": url, "status": "error", "count": 0}
        try:
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                count = 0
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        combined.add(line)
                        count += 1
                entry["status"] = "ok"
                entry["count"] = count
                get_app_logger().info(f"[BanlistSync] Fetched {count} IPs from {url}")
            else:
                get_app_logger().warning(
                    f"[BanlistSync] Source {url} returned HTTP {resp.status_code}"
                )
        except Exception as e:
            get_app_logger().warning(f"[BanlistSync] Failed to fetch {url}: {e}")

        sources_info.append(entry)

    with _lock:
        # Rebind, not clear()+update(): readers saw an empty banlist mid-update.
        _global_banlist = frozenset(combined)
        _banlist_sources.clear()
        _banlist_sources.extend(sources_info)
        _last_refresh = time.time()

    get_app_logger().info(
        f"[BanlistSync] Global banlist now has {len(combined)} IPs "
        f"across {len(sources_info)} sources"
    )
