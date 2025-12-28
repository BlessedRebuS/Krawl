#!/usr/bin/env python3

"""
Logging singleton module for the Krawl honeypot.
Provides two loggers: app (application) and access (HTTP access logs).
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Optional
from zoneinfo import ZoneInfo
from datetime import datetime


class TimezoneFormatter(logging.Formatter):
    """Custom formatter that respects configured timezone"""
    def __init__(self, fmt=None, datefmt=None, timezone: Optional[ZoneInfo] = None):
        super().__init__(fmt, datefmt)
        self.timezone = timezone or ZoneInfo('UTC')
    
    def formatTime(self, record, datefmt=None):
        """Override formatTime to use configured timezone"""
        dt = datetime.fromtimestamp(record.created, tz=self.timezone)
        if datefmt:
            return dt.strftime(datefmt)
        return dt.isoformat()


class LoggerManager:
    """Singleton logger manager for the application."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def initialize(self, log_dir: str = "logs", timezone: Optional[ZoneInfo] = None) -> None:
        """
        Initialize the logging system with rotating file handlers.

        Args:
            log_dir: Directory for log files (created if not exists)
            timezone: ZoneInfo timezone for log timestamps (defaults to UTC)
        """
        if self._initialized:
            return

        self.timezone = timezone or ZoneInfo('UTC')

        # Create log directory if it doesn't exist
        os.makedirs(log_dir, exist_ok=True)

        # Common format for all loggers
        log_format = TimezoneFormatter(
            "[%(asctime)s] %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            timezone=self.timezone
        )

        # Rotation settings: 1MB max, 5 backups
        max_bytes = 1048576  # 1MB
        backup_count = 5

        # Setup application logger
        self._app_logger = logging.getLogger("krawl.app")
        self._app_logger.setLevel(logging.INFO)
        self._app_logger.handlers.clear()

        app_file_handler = RotatingFileHandler(
            os.path.join(log_dir, "krawl.log"),
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        app_file_handler.setFormatter(log_format)
        self._app_logger.addHandler(app_file_handler)

        app_stream_handler = logging.StreamHandler()
        app_stream_handler.setFormatter(log_format)
        self._app_logger.addHandler(app_stream_handler)

        # Setup access logger
        self._access_logger = logging.getLogger("krawl.access")
        self._access_logger.setLevel(logging.INFO)
        self._access_logger.handlers.clear()

        access_file_handler = RotatingFileHandler(
            os.path.join(log_dir, "access.log"),
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        access_file_handler.setFormatter(log_format)
        self._access_logger.addHandler(access_file_handler)

        access_stream_handler = logging.StreamHandler()
        access_stream_handler.setFormatter(log_format)
        self._access_logger.addHandler(access_stream_handler)

        # Setup credential logger (special format, no stream handler)
        self._credential_logger = logging.getLogger("krawl.credentials")
        self._credential_logger.setLevel(logging.INFO)
        self._credential_logger.handlers.clear()

        # Credential logger uses a simple format: timestamp|ip|username|password|path
        credential_format = TimezoneFormatter("%(message)s", timezone=self.timezone)
        
        credential_file_handler = RotatingFileHandler(
            os.path.join(log_dir, "credentials.log"),
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        credential_file_handler.setFormatter(credential_format)
        self._credential_logger.addHandler(credential_file_handler)

        self._initialized = True

    @property
    def app(self) -> logging.Logger:
        """Get the application logger."""
        if not self._initialized:
            self.initialize()
        return self._app_logger

    @property
    def access(self) -> logging.Logger:
        """Get the access logger."""
        if not self._initialized:
            self.initialize()
        return self._access_logger

    @property
    def credentials(self) -> logging.Logger:
        """Get the credentials logger."""
        if not self._initialized:
            self.initialize()
        return self._credential_logger


# Module-level singleton instance
_logger_manager = LoggerManager()


def get_app_logger() -> logging.Logger:
    """Get the application logger instance."""
    return _logger_manager.app


def get_access_logger() -> logging.Logger:
    """Get the access logger instance."""
    return _logger_manager.access


def get_credential_logger() -> logging.Logger:
    """Get the credential logger instance."""
    return _logger_manager.credentials


def initialize_logging(log_dir: str = "logs", timezone: Optional[ZoneInfo] = None) -> None:
    """Initialize the logging system."""
    _logger_manager.initialize(log_dir, timezone)
