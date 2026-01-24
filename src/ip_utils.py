#!/usr/bin/env python3

"""
IP utility functions for filtering and validating IP addresses.
Provides common IP filtering logic used across the Krawl honeypot.
"""

import ipaddress
from typing import Optional


def is_local_or_private_ip(ip_str: str) -> bool:
    """
    Check if an IP address is local, private, or reserved.
    
    Filters out:
    - 127.0.0.1 (localhost)
    - 127.0.0.0/8 (loopback)
    - 10.0.0.0/8 (private network)
    - 172.16.0.0/12 (private network)
    - 192.168.0.0/16 (private network)
    - 0.0.0.0/8 (this network)
    - ::1 (IPv6 localhost)
    - ::ffff:127.0.0.0/104 (IPv6-mapped IPv4 loopback)
    
    Args:
        ip_str: IP address string
        
    Returns:
        True if IP is local/private/reserved, False if it's public
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_reserved
            or ip.is_link_local
            or str(ip) in ("0.0.0.0", "::1")
        )
    except ValueError:
        # Invalid IP address
        return True


def is_valid_public_ip(ip: str, server_ip: Optional[str] = None) -> bool:
    """
    Check if an IP is public and not the server's own IP.
    
    Returns True only if:
    - IP is not in local/private ranges AND
    - IP is not the server's own public IP (if server_ip provided)
    
    Args:
        ip: IP address string to check
        server_ip: Server's public IP (optional). If provided, filters out this IP too.
        
    Returns:
        True if IP is a valid public IP to track, False otherwise
    """
    return not is_local_or_private_ip(ip) and (server_ip is None or ip != server_ip)
