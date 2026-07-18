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
