#!/usr/bin/env python3

"""
IP utility functions for filtering and validating IP addresses.
Provides common IP filtering logic used across the Krawl honeypot.

The set of IPs to ignore (never track, ban, export, or persist) is
configurable via the `ignored_ips` config section — a list of single IPs or
CIDR ranges. See config.DEFAULT_IGNORED_IPS for the built-in defaults.
"""

import ipaddress
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
    "cloudfront": (
        "https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips",
    ),
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
