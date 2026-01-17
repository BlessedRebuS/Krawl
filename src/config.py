#!/usr/bin/env python3

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple
from zoneinfo import ZoneInfo
import time

import yaml


@dataclass
class Config:
    """Configuration class for the deception server"""
    port: int = 5000
    delay: int = 100  # milliseconds
    server_header: str = ""
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

    # Database settings
    database_path: str = "data/krawl.db"
    database_retention_days: int = 30

    # Analyzer settings
    http_risky_methods_threshold: float = None
    violated_robots_threshold: float = None
    uneven_request_timing_threshold: float = None
    uneven_request_timing_time_window_seconds: float = None
    user_agents_used_threshold: float = None
    attack_urls_threshold: float = None

    @classmethod
    def from_yaml(cls) -> 'Config':
        """Create configuration from YAML file"""
        config_location = os.getenv('CONFIG_LOCATION', 'config.yaml')
        config_path = Path(__file__).parent.parent / config_location

        try:
            with open(config_path, 'r') as f:
                data = yaml.safe_load(f)
        except FileNotFoundError:
            print(f"Error: Configuration file '{config_path}' not found.", file=sys.stderr)
            print(f"Please create a config.yaml file or set CONFIG_LOCATION environment variable.", file=sys.stderr)
            sys.exit(1)
        except yaml.YAMLError as e:
            print(f"Error: Invalid YAML in configuration file '{config_path}': {e}", file=sys.stderr)
            sys.exit(1)

        if data is None:
            data = {}

        # Extract nested values with defaults
        server = data.get('server', {})
        links = data.get('links', {})
        canary = data.get('canary', {})
        dashboard = data.get('dashboard', {})
        api = data.get('api', {})
        database = data.get('database', {})
        behavior = data.get('behavior', {})
        analyzer = data.get('analyzer') or {}

        # Handle dashboard_secret_path - auto-generate if null/not set
        dashboard_path = dashboard.get('secret_path')
        if dashboard_path is None:
            dashboard_path = f'/{os.urandom(16).hex()}'
        else:
            # ensure the dashboard path starts with a /
            if dashboard_path[:1] != "/":
                dashboard_path = f"/{dashboard_path}"

        return cls(
            port=server.get('port', 5000),
            delay=server.get('delay', 100),
            server_header=server.get('server_header',""),
            links_length_range=(
                links.get('min_length', 5),
                links.get('max_length', 15)
            ),
            links_per_page_range=(
                links.get('min_per_page', 10),
                links.get('max_per_page', 15)
            ),
            char_space=links.get('char_space', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'),
            max_counter=links.get('max_counter', 10),
            canary_token_url=canary.get('token_url'),
            canary_token_tries=canary.get('token_tries', 10),
            dashboard_secret_path=dashboard_path,
            api_server_url=api.get('server_url'),
            api_server_port=api.get('server_port', 8080),
            api_server_path=api.get('server_path', '/api/v2/users'),
            probability_error_codes=behavior.get('probability_error_codes', 0),
            database_path=database.get('path', 'data/krawl.db'),
            database_retention_days=database.get('retention_days', 30),
            http_risky_methods_threshold=analyzer.get('http_risky_methods_threshold', 0.1),
            violated_robots_threshold=analyzer.get('violated_robots_threshold', 0.1),
            uneven_request_timing_threshold=analyzer.get('uneven_request_timing_threshold', 0.5), # coefficient of variation
            uneven_request_timing_time_window_seconds=analyzer.get('uneven_request_timing_time_window_seconds', 300),
            user_agents_used_threshold=analyzer.get('user_agents_used_threshold', 2),
            attack_urls_threshold=analyzer.get('attack_urls_threshold', 1)
        )


_config_instance = None


def get_config() -> Config:
    """Get the singleton Config instance"""
    global _config_instance
    if _config_instance is None:
        _config_instance = Config.from_yaml()
    return _config_instance
