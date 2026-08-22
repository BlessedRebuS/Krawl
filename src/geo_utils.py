#!/usr/bin/env python3
"""
Geolocation utilities for IP lookups using ip-api.com.
"""

import ipaddress
from typing import Any

import requests

from logger import get_app_logger

app_logger = get_app_logger()


def fetch_ip_geolocation(ip_address: str) -> dict[str, Any] | None:
    """
    Fetch geolocation data for an IP address using ip-api.com.

    Results are persisted to the database by the caller (fetch_ip_rep task),
    so no in-memory caching is needed.

    Args:
        ip_address: IP address to lookup

    Returns:
        Dictionary containing geolocation data or None if lookup fails
    """
    try:
        if ipaddress.ip_address(ip_address).is_private:
            app_logger.debug(f"Skipping geolocation lookup for private IP {ip_address}")
            return None

        url = f"http://ip-api.com/json/{ip_address}"
        params = {
            "fields": "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,mobile,proxy,hosting,query"
        }

        response = requests.get(url, params=params, timeout=5)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            app_logger.warning(
                f"IP lookup failed for {ip_address}: {data.get('message')}"
            )
            return None

        app_logger.debug(f"Fetched geolocation for {ip_address}")
        return data

    except requests.RequestException as e:
        app_logger.warning(f"Geolocation API call failed for {ip_address}: {e}")
        return None
    except Exception as e:
        app_logger.error(f"Error fetching geolocation for {ip_address}: {e}")
        return None


def extract_geolocation_from_ip(ip_address: str) -> dict[str, Any] | None:
    """
    Extract geolocation data for an IP address.

    Args:
        ip_address: IP address to lookup

    Returns:
        Dictionary with city, country, lat, lon, and other geolocation data or None
    """
    geoloc_data = fetch_ip_geolocation(ip_address)
    if not geoloc_data:
        return None

    return {
        "city": geoloc_data.get("city"),
        "country": geoloc_data.get("country"),
        "country_code": geoloc_data.get("countryCode"),
        "region": geoloc_data.get("region"),
        "region_name": geoloc_data.get("regionName"),
        "latitude": geoloc_data.get("lat"),
        "longitude": geoloc_data.get("lon"),
        "timezone": geoloc_data.get("timezone"),
        "isp": geoloc_data.get("isp"),
        "org": geoloc_data.get("org"),
        "reverse": geoloc_data.get("reverse"),
        "is_proxy": geoloc_data.get("proxy"),
        "is_hosting": geoloc_data.get("hosting"),
    }


# Geolocation is a property of the network, not the address. One /32 in this
# honeypot produced 24,500 IPv6 addresses that would otherwise have cost 24,500
# identical API calls. Cache by /48 — the standard site allocation, so the answer
# is the same for every address inside it.
# ponytail: plain dict cleared wholesale at the cap. Swap for an LRU if the
# clear-and-refill ever shows up in the API call count.
_PREFIX_GEO: dict[str, dict[str, Any]] = {}
_PREFIX_GEO_MAX = 4096


def _geo_cache_key(ip_address: str) -> str | None:
    """The /48 an IPv6 address belongs to, or None for IPv4 (no sharing)."""
    if ":" not in ip_address:
        return None
    return ":".join(ip_address.split(":")[:3])


def extract_geolocation_shared(ip_address: str) -> dict[str, Any] | None:
    """extract_geolocation_from_ip, reusing the answer across an IPv6 /48."""
    key = _geo_cache_key(ip_address)
    if key is not None and key in _PREFIX_GEO:
        app_logger.debug(f"Reusing geolocation from {key}::/48 for {ip_address}")
        return dict(_PREFIX_GEO[key])

    data = extract_geolocation_from_ip(ip_address)

    # Only successful lookups are cached, so a failure never poisons a whole /48.
    if data and key is not None:
        if len(_PREFIX_GEO) >= _PREFIX_GEO_MAX:
            _PREFIX_GEO.clear()
        # Reverse DNS is per-address; everything else describes the network.
        _PREFIX_GEO[key] = {**data, "reverse": None}

    return data


def fetch_blocklist_data(ip_address: str) -> dict[str, Any] | None:
    """
    Fetch blocklist data for an IP address using lcrawl API.

    Args:
        ip_address: IP address to lookup

    Returns:
        Dictionary containing blocklist information or None if lookup fails
    """
    # This is now used only for ip reputation
    try:
        api_url = "https://iprep.lcrawl.com/api/iprep/"
        params = {"cidr": ip_address}
        headers = {"Content-Type": "application/json"}
        response = requests.get(api_url, headers=headers, params=params, timeout=10)

        if response.status_code == 200:
            payload = response.json()
            if payload.get("results"):
                results = payload["results"]
                # Get the most recent result (first in list, sorted by record_added)
                most_recent = results[0]
                list_on = most_recent.get("list_on", {})

                app_logger.debug(f"Fetched blocklist data for {ip_address}")
                return list_on
    except requests.RequestException as e:
        app_logger.warning(f"Failed to fetch blocklist data for {ip_address}: {e}")
    except Exception as e:
        app_logger.error(f"Error processing blocklist data for {ip_address}: {e}")

    return None
