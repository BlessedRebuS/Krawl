#!/usr/bin/env python3

import os
from dataclasses import dataclass
from typing import Optional, Tuple
from zoneinfo import ZoneInfo
import time


@dataclass
class Config:
    """Configuration class for the deception server"""
    port: int = 5000
    delay: int = 100  # milliseconds
    links_length_range: Tuple[int, int] = (5, 15)
    links_per_page_range: Tuple[int, int] = (10, 15)
    char_space: str = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    max_counter: int = 10
    canary_token_url: Optional[str] = None
    canary_token_tries: int = 10
    dashboard_secret_path: str = None
    api_server_url: Optional[str] = None
    api_server_port: int = 8080
    api_server_path: str = "/api/v2/users"
    probability_error_codes: int = 0  # Percentage (0-100)
    server_header: str = "Apache/2.2.22 (Ubuntu)"
    # Database settings
    database_path: str = "data/krawl.db"
    database_retention_days: int = 30
    timezone: str = None  # IANA timezone (e.g., 'America/New_York', 'Europe/Rome')
    
    @staticmethod
    # Try to fetch timezone before if not set
    def get_system_timezone() -> str:
        """Get the system's default timezone"""
        try:
            if os.path.islink('/etc/localtime'):
                tz_path = os.readlink('/etc/localtime')
                if 'zoneinfo/' in tz_path:
                    return tz_path.split('zoneinfo/')[-1]
            
            local_tz = time.tzname[time.daylight]
            if local_tz and local_tz != 'UTC':
                return local_tz
        except Exception:
            pass
        
        # Default fallback to UTC
        return 'UTC'
    
    def get_timezone(self) -> ZoneInfo:
        """Get configured timezone as ZoneInfo object"""
        if self.timezone:
            try:
                return ZoneInfo(self.timezone)
            except Exception:
                pass
        
        system_tz = self.get_system_timezone()
        try:
            return ZoneInfo(system_tz)
        except Exception:
            return ZoneInfo('UTC')

    @classmethod
    def from_env(cls) -> 'Config':
        """Create configuration from environment variables"""
        return cls(
            port=int(os.getenv('PORT', 5000)),
            delay=int(os.getenv('DELAY', 100)),
            links_length_range=(
                int(os.getenv('LINKS_MIN_LENGTH', 5)),
                int(os.getenv('LINKS_MAX_LENGTH', 15))
            ),
            links_per_page_range=(
                int(os.getenv('LINKS_MIN_PER_PAGE', 10)),
                int(os.getenv('LINKS_MAX_PER_PAGE', 15))
            ),
            char_space=os.getenv('CHAR_SPACE', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'),
            max_counter=int(os.getenv('MAX_COUNTER', 10)),
            canary_token_url=os.getenv('CANARY_TOKEN_URL'),
            canary_token_tries=int(os.getenv('CANARY_TOKEN_TRIES', 10)),
            dashboard_secret_path=os.getenv('DASHBOARD_SECRET_PATH', f'/{os.urandom(16).hex()}'),
            api_server_url=os.getenv('API_SERVER_URL'),
            api_server_port=int(os.getenv('API_SERVER_PORT', 8080)),
            api_server_path=os.getenv('API_SERVER_PATH', '/api/v2/users'),
            server_header=os.getenv('SERVER_HEADER', 'Apache/2.2.22 (Ubuntu)'),
            database_path=os.getenv('DATABASE_PATH', 'data/krawl.db'),
            database_retention_days=int(os.getenv('DATABASE_RETENTION_DAYS', 30)),
            probability_error_codes=int(os.getenv('PROBABILITY_ERROR_CODES', 0)),
            timezone=os.getenv('TIMEZONE')  # If not set, will use system timezone
        )
