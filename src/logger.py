#!/usr/bin/env python3

"""
Logging singleton module for the Krawl honeypot.
Provides two loggers: app (application) and access (HTTP access logs).
"""

import logging
import os
from logging.handlers import RotatingFileHandler


class LoggerManager:
    """Singleton logger manager for the application."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def initialize(self, log_dir: str = "logs", log_level: str = "INFO") -> None:
        """
        Initialize the logging system with rotating file handlers.loggers

        Args:
            log_dir: Directory for log files (created if not exists)
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        if self._initialized:
            return

        # Create log directory if it doesn't exist
        os.makedirs(log_dir, exist_ok=True)

        # Common format for all loggers
        log_format = logging.Formatter(
            "[%(asctime)s] %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # Rotation settings: 1MB max, 5 backups
        max_bytes = 1048576  # 1MB
        backup_count = 5

        level = getattr(logging, log_level.upper(), logging.INFO)

        # Setup application logger
        self._app_logger = logging.getLogger("krawl.app")
        self._app_logger.setLevel(level)
        self._app_logger.handlers.clear()

        app_file_handler = RotatingFileHandler(
            os.path.join(log_dir, "krawl.log"),
            maxBytes=max_bytes,
            backupCount=backup_count,
        )
        app_file_handler.setFormatter(log_format)
        self._app_logger.addHandler(app_file_handler)

        app_stream_handler = logging.StreamHandler()
        app_stream_handler.setFormatter(log_format)
        self._app_logger.addHandler(app_stream_handler)

        # Setup access logger
        self._access_logger = logging.getLogger("krawl.access")
        self._access_logger.setLevel(level)
        self._access_logger.handlers.clear()

        access_file_handler = RotatingFileHandler(
            os.path.join(log_dir, "access.log"),
            maxBytes=max_bytes,
            backupCount=backup_count,
        )
        access_file_handler.setFormatter(log_format)
        self._access_logger.addHandler(access_file_handler)

        access_stream_handler = logging.StreamHandler()
        access_stream_handler.setFormatter(log_format)
        self._access_logger.addHandler(access_stream_handler)

        # Setup credential logger (special format, no stream handler)
        self._credential_logger = logging.getLogger("krawl.credentials")
        self._credential_logger.setLevel(level)
        self._credential_logger.handlers.clear()

        # Credential logger uses a simple format: timestamp|ip|username|password|path
        credential_format = logging.Formatter("%(message)s")

        credential_file_handler = RotatingFileHandler(
            os.path.join(log_dir, "credentials.log"),
            maxBytes=max_bytes,
            backupCount=backup_count,
        )
        credential_file_handler.setFormatter(credential_format)
        self._credential_logger.addHandler(credential_file_handler)

        # Each krawl.* logger owns its handlers, so a record must stop there.
        # Without this it also travels up to `krawl` and on to the root logger,
        # and anything that has configured root — uvicorn, or a dependency
        # calling logging.basicConfig() — prints it a second time in its own
        # format. That is the duplicated access line:
        #     INFO:krawl.access:[GET] 1.2.3.4 - /x - 200      <- root
        #     [2026-08-30 18:27:48] INFO - [GET] 1.2.3.4 ...  <- ours
        self._app_logger.propagate = False
        self._access_logger.propagate = False
        self._credential_logger.propagate = False

        # tracker.py, generative_ai.py and deception_responses.py log to the
        # bare `krawl` parent. It had no handlers, so those records fell
        # through to root as well. Give it the app handlers and stop it there
        # too, so every krawl log lands in exactly one place.
        krawl_logger = logging.getLogger("krawl")
        krawl_logger.setLevel(level)
        krawl_logger.handlers.clear()
        krawl_logger.addHandler(app_file_handler)
        krawl_logger.addHandler(app_stream_handler)
        krawl_logger.propagate = False

        # Disable uvicorn's default access log to avoid duplicate entries
        # with the wrong (proxy) IP. Our custom access logger handles this.
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

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


def initialize_logging(log_dir: str = "logs", log_level: str = "INFO") -> None:
    """Initialize the logging system."""
    _logger_manager.initialize(log_dir, log_level)
