#!/usr/bin/env python3
"""
Geolocation utilities for reverse geocoding and city lookups.
"""

import requests
from typing import Optional, Tuple
from logger import get_app_logger

app_logger = get_app_logger()

# Simple city name cache to avoid repeated API calls
_city_cache = {}


def reverse_geocode_city(latitude: float, longitude: float) -> Optional[str]:
    """
    Reverse geocode coordinates to get city name using Nominatim (OpenStreetMap).

    Args:
        latitude: Latitude coordinate
        longitude: Longitude coordinate

    Returns:
        City name or None if not found
    """
    # Check cache first
    cache_key = f"{latitude},{longitude}"
    if cache_key in _city_cache:
        return _city_cache[cache_key]

    try:
        # Use Nominatim reverse geocoding API (free, no API key required)
        url = "https://nominatim.openstreetmap.org/reverse"
        params = {
            "lat": latitude,
            "lon": longitude,
            "format": "json",
            "zoom": 10,  # City level
            "addressdetails": 1
        }
        headers = {
            "User-Agent": "Krawl-Honeypot/1.0"  # Required by Nominatim ToS
        }

        response = requests.get(url, params=params, headers=headers, timeout=5)
        response.raise_for_status()

        data = response.json()
        address = data.get("address", {})

        # Try to get city from various possible fields
        city = (
            address.get("city") or
            address.get("town") or
            address.get("village") or
            address.get("municipality") or
            address.get("county")
        )

        # Cache the result
        _city_cache[cache_key] = city

        if city:
            app_logger.debug(f"Reverse geocoded {latitude},{longitude} to {city}")

        return city

    except requests.RequestException as e:
        app_logger.warning(f"Reverse geocoding failed for {latitude},{longitude}: {e}")
        return None
    except Exception as e:
        app_logger.error(f"Error in reverse geocoding: {e}")
        return None


def get_most_recent_geoip_data(results: list) -> Optional[dict]:
    """
    Extract the most recent geoip_data from API results.
    Results are assumed to be sorted by record_added (most recent first).

    Args:
        results: List of result dictionaries from IP reputation API

    Returns:
        Most recent geoip_data dict or None
    """
    if not results:
        return None

    # The first result is the most recent (sorted by record_added)
    most_recent = results[0]
    return most_recent.get("geoip_data")


def extract_city_from_coordinates(geoip_data: dict) -> Optional[str]:
    """
    Extract city name from geoip_data using reverse geocoding.

    Args:
        geoip_data: Dictionary containing location_latitude and location_longitude

    Returns:
        City name or None
    """
    if not geoip_data:
        return None

    latitude = geoip_data.get("location_latitude")
    longitude = geoip_data.get("location_longitude")

    if latitude is None or longitude is None:
        return None

    return reverse_geocode_city(latitude, longitude)
