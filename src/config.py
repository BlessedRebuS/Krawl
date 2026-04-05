#!/usr/bin/env python3

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple
from zoneinfo import ZoneInfo
import time
from logger import get_app_logger
import socket
import time
import requests
import yaml


@dataclass
class Config:
    """Configuration class for the deception server"""

    # Deployment mode: "standalone" (SQLite + in-memory) or "scalable" (PostgreSQL + Redis)
    mode: str = "standalone"

    # PostgreSQL settings (scalable mode)
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_user: str = "krawl"
    postgres_password: str = "krawl"
    postgres_database: str = "krawl"

    # Redis settings (scalable mode)
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: Optional[str] = None
    redis_cache_ttl: int = 600
    redis_hot_ttl: int = 30
    redis_table_ttl: int = 120

    port: int = 5000
    delay: int = 100  # milliseconds
    server_header: str = ""
    links_length_range: Tuple[int, int] = (5, 15)
    links_per_page_range: Tuple[int, int] = (10, 15)
    char_space: str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    max_counter: int = 10
    canary_token_url: Optional[str] = None
    canary_token_tries: int = 10
    dashboard_secret_path: str = None
    dashboard_password: Optional[str] = None
    dashboard_password_generated: bool = False
    dashboard_cache_warmup: bool = True
    probability_error_codes: int = 0  # Percentage (0-100)

    # Crawl limiting settings - for legitimate vs malicious crawlers
    max_pages_limit: int = (
        100  # Max pages limit for good crawlers and regular users (and bad crawlers/attackers if infinite_pages_for_malicious is False)
    )
    infinite_pages_for_malicious: bool = True  # Infinite pages for malicious crawlers
    ban_duration_seconds: int = 600  # Ban duration in seconds for IPs exceeding limits

    # exporter settings
    exports_path: str = "exports"

    # backup job settings
    backups_path: str = "backups"
    backups_enabled: bool = False
    backups_cron: str = "*/30 * * * *"
    # Database settings
    database_path: str = "data/krawl.db"
    database_retention_days: int = 30
    database_persist_suspicious_only: bool = False

    # Analyzer settings
    http_risky_methods_threshold: float = None
    violated_robots_threshold: float = None
    uneven_request_timing_threshold: float = None
    uneven_request_timing_time_window_seconds: float = None
    user_agents_used_threshold: float = None
    attack_urls_threshold: float = None

    # Tarpit settings - opt-in feature to slow down and confuse AI crawlers
    tarpit_enabled: bool = False
    tarpit_delay_seconds: int = 5

    log_level: str = "INFO"

    # AI generation settings
    ai_enabled: bool = False
    ai_provider: str = "openrouter"
    ai_api_key: Optional[str] = None
    ai_model: str = "nvidia/nemotron-3-super-120b-a12b:free"
    ai_prompt: str = ""
    ai_timeout: int = 60
    ai_max_daily_requests: int = 0
    ai_reasoning_enabled: bool = True
    ai_reasoning_effort: str = "medium"

    _server_ip: Optional[str] = None
    _server_ip_resolved: bool = False

    def resolve_server_ip(self) -> None:
        """
        Resolve the server's public IP once at startup.
        Stores the result (or None) permanently — no repeated lookups.
        """
        if self._server_ip_resolved:
            return

        try:
            ip_detection_services = [
                "https://api.ipify.org",
                "http://ident.me",
                "https://ifconfig.me",
            ]

            for service_url in ip_detection_services:
                try:
                    response = requests.get(service_url, timeout=5)
                    if response.status_code == 200:
                        ip = response.text.strip()
                        if ip:
                            self._server_ip = ip
                            self._server_ip_resolved = True
                            return
                except requests.RequestException:
                    continue

            get_app_logger().warning(
                "Could not determine server IP from external services. "
                "All IPs will be tracked (including potential server IP)."
            )
        except Exception as e:
            get_app_logger().warning(
                f"Could not determine server IP address: {e}. "
                "All IPs will be tracked (including potential server IP)."
            )

        self._server_ip_resolved = True

    def get_server_ip(self) -> Optional[str]:
        """Get the server's public IP (resolved once at startup)."""
        return self._server_ip

    @classmethod
    def from_yaml(cls) -> "Config":
        """Create configuration from YAML file"""
        config_location = os.getenv("CONFIG_LOCATION", "config.yaml")
        config_path = Path(__file__).parent.parent / config_location

        try:
            with open(config_path, "r") as f:
                data = yaml.safe_load(f)
        except FileNotFoundError:
            print(
                f"Error: Configuration file '{config_path}' not found.", file=sys.stderr
            )
            print(
                f"Please create a config.yaml file or set CONFIG_LOCATION environment variable.",
                file=sys.stderr,
            )
            sys.exit(1)
        except yaml.YAMLError as e:
            print(
                f"Error: Invalid YAML in configuration file '{config_path}': {e}",
                file=sys.stderr,
            )
            sys.exit(1)

        if data is None:
            data = {}

        # Extract nested values with defaults
        mode = data.get("mode", "standalone")
        postgres_cfg = data.get("postgres", {})
        redis_cfg = data.get("redis", {})
        server = data.get("server", {})
        links = data.get("links", {})
        canary = data.get("canary", {})
        dashboard = data.get("dashboard", {})
        api = data.get("api", {})
        exports = data.get("exports", {})
        backups = data.get("backups", {})
        database = data.get("database", {})
        behavior = data.get("behavior", {})
        analyzer = data.get("analyzer") or {}
        crawl = data.get("crawl", {})
        tarpit = data.get("tarpit", {})
        logging_cfg = data.get("logging", {})
        ai = data.get("ai", {})

        # Handle dashboard_secret_path - auto-generate if null/not set
        dashboard_path = dashboard.get("secret_path")
        if dashboard_path is None:
            dashboard_path = f"/{os.urandom(16).hex()}"
        else:
            # ensure the dashboard path starts with a /
            if dashboard_path[:1] != "/":
                dashboard_path = f"/{dashboard_path}"

        # Handle dashboard_password - auto-generate if null/not set
        dashboard_password = dashboard.get("password")
        dashboard_password_generated = False
        if dashboard_password is None:
            dashboard_password = os.urandom(25).hex()
            dashboard_password_generated = True

        # Validate mode
        if mode not in ("standalone", "scalable"):
            print(
                f"Error: Invalid mode '{mode}'. Must be 'standalone' or 'scalable'.",
                file=sys.stderr,
            )
            sys.exit(1)

        return cls(
            mode=mode,
            postgres_host=postgres_cfg.get("host", "localhost"),
            postgres_port=postgres_cfg.get("port", 5432),
            postgres_user=postgres_cfg.get("user", "krawl"),
            postgres_password=postgres_cfg.get("password", "krawl"),
            postgres_database=postgres_cfg.get("database", "krawl"),
            redis_host=redis_cfg.get("host", "localhost"),
            redis_port=redis_cfg.get("port", 6379),
            redis_db=redis_cfg.get("db", 0),
            redis_password=redis_cfg.get("password") or None,
            redis_cache_ttl=redis_cfg.get("cache_ttl", 600),
            redis_hot_ttl=redis_cfg.get("hot_ttl", 30),
            redis_table_ttl=redis_cfg.get("table_ttl", 120),
            port=server.get("port", 5000),
            delay=server.get("delay", 100),
            server_header=server.get("server_header", ""),
            links_length_range=(
                links.get("min_length", 5),
                links.get("max_length", 15),
            ),
            links_per_page_range=(
                links.get("min_per_page", 10),
                links.get("max_per_page", 15),
            ),
            char_space=links.get(
                "char_space",
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            ),
            max_counter=links.get("max_counter", 10),
            canary_token_url=canary.get("token_url"),
            canary_token_tries=canary.get("token_tries", 10),
            dashboard_secret_path=dashboard_path,
            dashboard_password=dashboard_password,
            dashboard_password_generated=dashboard_password_generated,
            dashboard_cache_warmup=dashboard.get("cache_warmup", True),
            probability_error_codes=behavior.get("probability_error_codes", 0),
            exports_path=exports.get("path", "exports"),
            backups_path=backups.get("path", "backups"),
            backups_enabled=backups.get("enabled", False),
            backups_cron=backups.get("cron"),
            database_path=database.get("path", "data/krawl.db"),
            database_retention_days=database.get("retention_days", 30),
            database_persist_suspicious_only=database.get(
                "persist_suspicious_only", False
            ),
            http_risky_methods_threshold=analyzer.get(
                "http_risky_methods_threshold", 0.1
            ),
            violated_robots_threshold=analyzer.get("violated_robots_threshold", 0.1),
            uneven_request_timing_threshold=analyzer.get(
                "uneven_request_timing_threshold", 0.5
            ),  # coefficient of variation
            uneven_request_timing_time_window_seconds=analyzer.get(
                "uneven_request_timing_time_window_seconds", 300
            ),
            user_agents_used_threshold=analyzer.get("user_agents_used_threshold", 2),
            attack_urls_threshold=analyzer.get("attack_urls_threshold", 1),
            infinite_pages_for_malicious=crawl.get(
                "infinite_pages_for_malicious", True
            ),
            max_pages_limit=crawl.get("max_pages_limit", 250),
            ban_duration_seconds=crawl.get("ban_duration_seconds", 600),
            tarpit_enabled=tarpit.get("enabled", False),
            tarpit_delay_seconds=tarpit.get("delay_seconds", 5),
            log_level=os.getenv(
                "KRAWL_LOG_LEVEL", logging_cfg.get("level", "INFO")
            ).upper(),
            ai_enabled=ai.get("enabled", False),
            ai_provider=ai.get("provider", "openrouter").lower(),
            ai_api_key=ai.get("api_key"),
            ai_model=ai.get("model", "nvidia/nemotron-3-super-120b-a12b:free"),
            ai_reasoning_enabled=ai.get("reasoning", {}).get("enabled", True),
            ai_reasoning_effort=ai.get("reasoning", {}).get("effort", "medium"),
            ai_prompt=ai.get(
                "prompt",
                """Your goal is to create a plausible but fake intentionally vulnerable page that might appear on a real server, that can distract attackers. 
Your input will be a query path, that the attacker asked for. 

Follow this rules:
1. You must output ONLY the HTML, nothing else
2. Include realistic content if necessary (links, text, forms, etc.)
3. Do not add markdown, code blocks, or explanations
4. Do not include any file in the html, generate everything needed in one single file
5. Include proper HTML structure with head and body tags
6. If the request is a common attack vector (e.g., SQLi, XSS), include fake data in response
7. If the request has a file extension, generate a RAW content relevant to that type (e.g. a fake json for .json requests)

Path: {path}{query_part}
Generate the complete HTML page.""",
            ),
            ai_timeout=ai.get("timeout", 60),
            ai_max_daily_requests=ai.get("max_daily_requests", 0),
        )


def __get_env_from_config(config: str) -> str:

    env = config.upper().replace(".", "_").replace("-", "__").replace(" ", "_")

    return f"KRAWL_{env}"


def override_config_from_env(config: Config = None):
    """Initialize configuration from environment variables"""

    for field in config.__dataclass_fields__:

        env_var = __get_env_from_config(field)
        if env_var in os.environ:

            get_app_logger().info(
                f"Overriding config '{field}' from environment variable '{env_var}'"
            )
            try:
                field_type = config.__dataclass_fields__[field].type
                env_value = os.environ[env_var]
                # If password is overridden, it's no longer auto-generated
                if field == "dashboard_password":
                    config.dashboard_password_generated = False
                if field_type == int:
                    setattr(config, field, int(env_value))
                elif field_type == float:
                    setattr(config, field, float(env_value))
                elif field_type == bool:
                    # Handle boolean values (case-insensitive: true/false, yes/no, 1/0)
                    setattr(config, field, env_value.lower() in ("true", "yes", "1"))
                elif field_type == Tuple[int, int]:
                    parts = env_value.split(",")
                    if len(parts) == 2:
                        setattr(config, field, (int(parts[0]), int(parts[1])))
                else:
                    # Treat empty strings as None for Optional fields (e.g. passwords)
                    setattr(config, field, env_value if env_value else None)
            except Exception as e:
                get_app_logger().error(
                    f"Error overriding config '{field}' from environment variable '{env_var}': {e}"
                )


_config_instance = None


def get_config() -> Config:
    """Get the singleton Config instance"""
    global _config_instance
    if _config_instance is None:
        _config_instance = Config.from_yaml()

        override_config_from_env(_config_instance)

    return _config_instance
