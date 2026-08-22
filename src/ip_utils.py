#!/usr/bin/env python3

"""
IP utility functions for filtering and validating IP addresses.
Provides common IP filtering logic used across the Krawl honeypot.

The set of IPs to ignore (never track, ban, export, or persist) is
configurable via the `ignored_ips` config section — a list of single IPs or
CIDR ranges. See config.DEFAULT_IGNORED_IPS for the built-in defaults.
"""

import ipaddress
import threading
import time
from functools import lru_cache

from logger import get_app_logger


@lru_cache(maxsize=8)
def _parse_ignored_networks(entries: tuple[str, ...]) -> tuple:
    """Parse ignored_ips entries into ip_network objects (cached per entry set).

    Invalid entries are skipped with a warning so one bad line can't break
    filtering for the rest.
    """
    networks = []
    for entry in entries:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            get_app_logger().warning(f"Ignoring invalid ignored_ips entry: {entry!r}")
    return tuple(networks)


def is_ignored_ip(ip_str: str, ignored_entries: list[str] | None = None) -> bool:
    """
    Check whether an IP should be ignored (never tracked, banned, exported,
    or persisted), based on the configurable ignored_ips list.

    Args:
        ip_str: IP address string.
        ignored_entries: Optional explicit list of IP/CIDR strings. When None,
            the current config's `ignored_ips` is used.

    Returns:
        True if the IP matches the ignore list, or is not a valid IP address
        (malformed input is treated as ignorable, mirroring the previous guard).
    """
    if ignored_entries is None:
        from config import get_config

        ignored_entries = get_config().ignored_ips

    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True

    for net in _parse_ignored_networks(tuple(ignored_entries)):
        if ip.version == net.version and ip in net:
            return True
    return False


def is_valid_public_ip(ip: str, server_ip: str | None = None) -> bool:
    """
    Check if an IP is trackable: not in the ignore list and not the server's
    own IP.

    Args:
        ip: IP address string to check.
        server_ip: Server's public IP (optional). If provided, filters it out.

    Returns:
        True if the IP is a valid public IP to track, False otherwise.
    """
    return not is_ignored_ip(ip) and (server_ip is None or ip != server_ip)


# Published CDN ranges per provider, fetched at export time (never stored).
CDN_PROVIDER_URLS = {
    "cloudflare": (
        "https://www.cloudflare.com/ips-v4",
        "https://www.cloudflare.com/ips-v6",
    ),
    "fastly": ("https://api.fastly.com/public-ip-list",),
    "cloudfront": ("https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips",),
    "google": ("https://www.gstatic.com/ipranges/goog.json",),
    "bunny": ("https://bunnycdn.com/api/system/edgeserverlist",),
}


def _cidrs_in(payload):
    """Yield every CIDR-looking string in a text or JSON response body."""
    if isinstance(payload, str):
        yield from payload.split()
    elif isinstance(payload, dict):
        for v in payload.values():
            yield from _cidrs_in(v)
    elif isinstance(payload, list):
        for v in payload:
            yield from _cidrs_in(v)


@lru_cache(maxsize=8)
def _cdn_networks(provider: str, _hour_bucket: int) -> tuple:
    """Fetch a provider's published ranges. Cached in memory for an hour.

    Never persisted to disk; a fetch failure yields no networks for that URL
    so export still works (just without that provider filtered out).
    """
    import requests

    networks = []
    for url in CDN_PROVIDER_URLS.get(provider, ()):
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            try:
                body = resp.json()
            except ValueError:
                body = resp.text
            for entry in _cidrs_in(body):
                try:
                    networks.append(ipaddress.ip_network(entry.strip(), strict=False))
                except ValueError:
                    continue
        except Exception as e:
            get_app_logger().warning(f"Could not fetch CDN ranges from {url}: {e}")
    return tuple(networks)


def get_cdn_networks(providers) -> tuple:
    """Published ranges for the given providers, refreshed at most once per hour."""
    import time

    bucket = int(time.time() // 3600)
    return tuple(
        net
        for p in providers
        if p in CDN_PROVIDER_URLS
        for net in _cdn_networks(p, bucket)
    )


def is_cdn_ip(ip_str: str, networks: tuple) -> bool:
    """True if the IP falls inside one of the given CDN ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip.version == net.version and ip in net for net in networks)


# ---------------------------------------------------------------------------
# First-sighting ledger: keeping single-request IPv6 addresses out of the DB
# ---------------------------------------------------------------------------
# Rotating proxy pools burn a fresh IPv6 address on every request: one operator
# produced ~24,500 addresses from a single /32, each with exactly one request,
# and 42% of ip_stats was IPv6 rows that would never be seen again. Every one
# cost a row, an analyzer pass and a geolocation lookup for a known network.
#
# So an IPv6 address earns its row on the *second* sighting. IPv4 is unaffected
# (addresses are scarce there and reuse is the norm), and anything suspicious is
# persisted immediately, so a one-shot attacker is never lost.

_SEEN_PREFIX = "krawl:seen:"

# ponytail: a fixed window, not a tuned one. Long enough that a real client
# returning within the session gets its row, short enough that the ledger stays
# small. Make it configurable if operators need to trade rows for fidelity.
FIRST_SIGHT_TTL = 1800  # 30 minutes

_seen_lock = threading.Lock()
_seen: dict[str, float] = {}  # ip -> expires_at


def _prune_seen(now: float) -> None:
    """Drop expired entries. Cheap: the dict only holds one TTL window."""
    for ip in [ip for ip, expires in _seen.items() if expires <= now]:
        del _seen[ip]


def seen_before(ip: str, ttl: int = FIRST_SIGHT_TTL) -> bool:
    """Record a sighting of `ip`; return True if it was already sighted.

    Redis in scalable mode so the two sightings can land on different pods, a
    process-local dict in standalone. Same split as auth_store.

    First call within the window returns False, every later one returns True.
    """
    from dashboard_cache import get_backend, get_redis_client

    if get_backend() == "scalable":
        r = get_redis_client()
        if r is not None:
            # SET NX returns truthy only when the key did not exist, so a
            # falsey result means "already there" — one round-trip, no race.
            return not r.set(f"{_SEEN_PREFIX}{ip}", "1", nx=True, ex=ttl)

    now = time.time()
    with _seen_lock:
        _prune_seen(now)
        if _seen.get(ip, 0) > now:
            return True
        _seen[ip] = now + ttl
        return False


def defer_persist(ip: str, is_suspicious: bool, is_honeypot_trigger: bool) -> bool:
    """True when this request should not yet create an ip_stats row.

    Only ever defers a first-sighting IPv6 address that did nothing suspicious.
    """
    if ":" not in ip:  # IPv4 — persist immediately, as before
        return False
    if is_suspicious or is_honeypot_trigger:
        return False
    return not seen_before(ip)
