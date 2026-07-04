import threading
import time

import requests

from logger import get_app_logger

CATEGORY_COLORS = {
    "attacker": "#f85149",
    "bad_crawler": "#d29922",
    "regular_user": "#58a6ff",
    "good_crawler": "#3fb950",
    "timed_out": "#db61a2",
    "unknown": "#8b949e",
}

_global_banlist: set[str] = set()
_banlist_sources: list[dict] = []
_last_refresh: float = 0.0
_lock = threading.Lock()


def get_global_banlist() -> set[str]:
    """Return the current in-memory global banlist (IPs from all sources)."""
    with _lock:
        return _global_banlist.copy()


def get_banlist_sources() -> list[dict]:
    """Return list of sources with their status for dashboard display."""
    with _lock:
        return list(_banlist_sources)


def refresh_banlist_sources(*, source_urls: list[str] | None = None) -> None:
    """Fetch all configured banlist sources and merge IPs into the global set.

    Called on startup and periodically by the refresh_banlist task.
    """
    from config import get_config

    config = get_config()
    urls = source_urls if source_urls is not None else (config.banlist_sources or [])

    if not urls:
        with _lock:
            _global_banlist.clear()
            _banlist_sources.clear()
            _last_refresh = time.time()
        return

    combined: set[str] = set()
    sources_info: list[dict] = []

    per_source_ips: dict[str, set[str]] = {}

    for url in urls:
        entry: dict = {"url": url, "status": "error", "count": 0}
        source_ips: set[str] = set()
        try:
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        combined.add(line)
                        source_ips.add(line)
                entry["status"] = "ok"
                entry["count"] = len(source_ips)
                get_app_logger().info(
                    f"[BanlistSync] Fetched {len(source_ips)} IPs from {url}"
                )
            else:
                get_app_logger().warning(
                    f"[BanlistSync] Source {url} returned HTTP {resp.status_code}"
                )
        except Exception as e:
            get_app_logger().warning(f"[BanlistSync] Failed to fetch {url}: {e}")

        per_source_ips[url] = source_ips
        sources_info.append(entry)

    # Batch-query local DB for category breakdown of the fetched IPs
    _enrich_source_categories(sources_info, per_source_ips)

    with _lock:
        _global_banlist.clear()
        _global_banlist.update(combined)
        _banlist_sources.clear()
        _banlist_sources.extend(sources_info)
        _last_refresh = time.time()

    get_app_logger().info(
        f"[BanlistSync] Global banlist now has {len(combined)} IPs "
        f"across {len(sources_info)} sources"
    )


def _enrich_source_categories(
    sources_info: list[dict],
    per_source_ips: dict[str, set[str]],
) -> None:
    """Query local DB to classify fetched IPs by category for each source."""
    all_ips = set()
    for ips in per_source_ips.values():
        all_ips.update(ips)

    if not all_ips:
        return

    ip_category: dict[str, str] = {}
    try:
        from database.core import get_database
        from models import IpStats

        db = get_database()
        if not db.session:
            return
        session = db.session
        rows = (
            session.query(IpStats.ip, IpStats.category)
            .filter(IpStats.ip.in_(list(all_ips)))
            .all()
        )
        for ip, cat in rows:
            ip_category[ip] = cat or "unknown"
        db.close_session()
    except Exception as e:
        get_app_logger().warning(
            f"[BanlistSync] Failed to categorize source IPs: {e}"
        )
        return

    for entry in sources_info:
        url = entry["url"]
        source_ips = per_source_ips.get(url, set())
        if not source_ips:
            continue
        cats: dict[str, int] = {}
        for ip in source_ips:
            cat = ip_category.get(ip, "unknown")
            cats[cat] = cats.get(cat, 0) + 1
        entry["categories"] = cats
