import json
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

# Outside krawl:cache:: this payload is durable shared state with its own TTL,
# not a disposable cache entry.
PUBLISHED_KEY: str = "krawl:task:banlist"


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

    # Three refresh intervals, so a payload whose publisher permanently
    # disappeared ages out instead of being served forever.
    from config import get_config as _get_config

    publish(_get_config().banlist_refresh_interval * 3)


def publish(ttl_seconds: int) -> bool:
    """Publish the current banlist so peer pods need not fetch the sources.

    Returns True when a payload was written. Standalone mode has no peers, so it
    returns False without touching anything.

    The per-source status records travel with the IPs, so the dashboard's source
    health reflects the fetch the cluster actually performed rather than
    whichever pod happened to answer the request.
    """
    from dashboard_cache import get_backend, get_redis_client

    if get_backend() != "scalable":
        return False

    redis_client = get_redis_client()
    if redis_client is None:
        return False

    with _lock:
        payload = json.dumps(
            {
                "ips": sorted(_global_banlist),
                "sources": list(_banlist_sources),
            }
        )

    redis_client.setex(PUBLISHED_KEY, ttl_seconds, payload)
    get_app_logger().info(
        f"[BanlistSync] Published {len(_global_banlist)} IPs for peer pods"
    )
    return True


def load_published() -> bool:
    """Adopt the banlist a peer pod published. True when one was found.

    Leaves the current list untouched and returns False when nothing has been
    published yet, so a cold cluster falls through to fetching the sources.
    """
    global _global_banlist, _last_refresh

    from dashboard_cache import get_backend, get_redis_client

    if get_backend() != "scalable":
        return False

    redis_client = get_redis_client()
    if redis_client is None:
        return False

    raw = redis_client.get(PUBLISHED_KEY)
    if not raw:
        return False

    payload = json.loads(raw)

    # Rebind rather than mutate: the ban-check middleware reads this frozenset
    # on every request and must never observe it half-populated.
    with _lock:
        _global_banlist = frozenset(payload.get("ips", []))
        _banlist_sources.clear()
        _banlist_sources.extend(payload.get("sources", []))
        _last_refresh = time.time()

    get_app_logger().info(
        f"[BanlistSync] Adopted published banlist: {len(_global_banlist)} IPs"
    )
    return True
