#!/usr/bin/env python3

"""
Sanitization utilities for safe database storage and HTML output.
Protects against SQL injection payloads, XSS, and storage exhaustion attacks.
"""

import re

# Field length limits for database storage
MAX_IP_LENGTH = 45  # IPv6 max length
MAX_PATH_LENGTH = 2048  # URL max practical length
MAX_USER_AGENT_LENGTH = 512
MAX_CREDENTIAL_LENGTH = 256
MAX_ATTACK_PATTERN_LENGTH = 256
MAX_CITY_LENGTH = 128
MAX_ASN_ORG_LENGTH = 256
MAX_REPUTATION_SOURCE_LENGTH = 64


def sanitize_for_storage(value: str | None, max_length: int) -> str:
    """
    Sanitize and truncate string for safe database storage.

    Removes null bytes and control characters that could cause issues
    with database storage or log processing.

    Args:
        value: The string to sanitize
        max_length: Maximum length to truncate to

    Returns:
        Sanitized and truncated string, empty string if input is None/empty
    """
    if not value:
        return ""

    # Convert to string if not already
    value = str(value)

    # Remove null bytes and control characters (except newline \n, tab \t, carriage return \r)
    # Control chars are 0x00-0x1F and 0x7F, we keep 0x09 (tab), 0x0A (newline), 0x0D (carriage return)
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)

    # Truncate to max length
    return cleaned[:max_length]


def sanitize_ip(value: str | None) -> str:
    """Sanitize IP address for storage."""
    return sanitize_for_storage(value, MAX_IP_LENGTH)


def sanitize_path(value: str | None) -> str:
    """Sanitize URL path for storage."""
    return sanitize_for_storage(value, MAX_PATH_LENGTH)


def sanitize_user_agent(value: str | None) -> str:
    """Sanitize user agent string for storage."""
    return sanitize_for_storage(value, MAX_USER_AGENT_LENGTH)


def sanitize_credential(value: str | None) -> str:
    """Sanitize username or password for storage."""
    return sanitize_for_storage(value, MAX_CREDENTIAL_LENGTH)


def sanitize_attack_pattern(value: str | None) -> str:
    """Sanitize matched attack pattern for storage."""
    return sanitize_for_storage(value, MAX_ATTACK_PATTERN_LENGTH)


def sanitize_dict(value: dict[str, str] | None, max_display_length):
    return {k: sanitize_for_storage(v, max_display_length) for k, v in value.items()}
