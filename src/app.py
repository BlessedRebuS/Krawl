#!/usr/bin/env python3

"""
FastAPI application factory for the Krawl honeypot.
Replaces the old http.server-based server.py.
"""

import gc
import sys
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles

from config import get_config
from tracker import AccessTracker, set_tracker
from database import initialize_database
from dashboard_cache import initialize_cache, flush_all as flush_cache
from tasks_master import get_tasksmaster
from logger import initialize_logging, get_app_logger, get_access_logger
from generators import random_server_header


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    gc.set_threshold(700, 10, 5)

    config = get_config()

    # Initialize logging
    initialize_logging(log_level=config.log_level)
    app_logger = get_app_logger()

    # Initialize database and run pending migrations before accepting traffic
    try:
        if config.mode == "scalable":
            app_logger.info(f"Initializing database in scalable mode (PostgreSQL)")
            initialize_database(
                database_path=config.database_path,
                mode="scalable",
                postgres_config={
                    "host": config.postgres_host,
                    "port": config.postgres_port,
                    "user": config.postgres_user,
                    "password": config.postgres_password,
                    "database": config.postgres_database,
                },
            )
        else:
            app_logger.info(f"Initializing database at: {config.database_path}")
            initialize_database(config.database_path)
        app_logger.info("Database ready")
    except Exception as e:
        if config.mode == "scalable":
            app_logger.error(
                f"Database initialization failed in scalable mode: {e}. "
                "Cannot safely continue without PostgreSQL; exiting."
            )
            import sys

            sys.exit(1)
        else:
            app_logger.warning(
                f"Database initialization failed: {e}. Continuing with in-memory only."
            )

    # Initialize cache backend (in-memory dict for standalone, Redis for scalable)
    try:
        if config.mode == "scalable":
            initialize_cache(
                mode="scalable",
                redis_config={
                    "host": config.redis_host,
                    "port": config.redis_port,
                    "db": config.redis_db,
                    "password": config.redis_password,
                },
                ttl_config={
                    "cache_ttl": config.redis_cache_ttl,
                    "hot_ttl": config.redis_hot_ttl,
                    "table_ttl": config.redis_table_ttl,
                },
            )
            app_logger.info(
                f"Cache initialized with Redis at {config.redis_host}:{config.redis_port}"
            )
        else:
            initialize_cache(mode="standalone")
            app_logger.info("Cache initialized with in-memory backend")
    except Exception as e:
        app_logger.warning(
            f"Redis cache initialization failed: {e}. Falling back to in-memory cache."
        )
        initialize_cache(mode="standalone")

    # Flush stale cache from previous run so the pod starts fresh
    try:
        flush_cache()
        app_logger.info("Cache flushed on startup")
    except Exception as e:
        app_logger.warning(f"Cache flush on startup failed: {e}")

    # Resolve server IP once (used to exclude self-traffic from stats)
    config.resolve_server_ip()
    if config.get_server_ip():
        app_logger.info(f"Server public IP: {config.get_server_ip()}")
    else:
        app_logger.warning("Server public IP could not be determined")

    # Log AI configuration status
    from generative_ai import is_ai_enabled, get_provider, get_model

    if is_ai_enabled():
        provider = get_provider()
        model = get_model()
        app_logger.info(f"AI generation enabled - Provider: {provider}, Model: {model}")
    else:
        app_logger.info(
            "AI generation disabled - Cached AI pages will still be served if available"
        )

    # Initialize tracker
    tracker = AccessTracker(config.max_pages_limit, config.ban_duration_seconds)
    set_tracker(tracker)

    # Store in app.state for dependency injection
    app.state.config = config
    app.state.tracker = tracker

    # Load webpages file if provided via env var
    webpages = None
    webpages_file = os.environ.get("KRAWL_WEBPAGES_FILE")
    if webpages_file:
        try:
            with open(webpages_file, "r") as f:
                webpages = f.readlines()
            if not webpages:
                app_logger.warning(
                    "The webpages file was empty. Using randomly generated links."
                )
                webpages = None
        except IOError:
            app_logger.warning(
                "Can't read webpages file. Using randomly generated links."
            )
    app.state.webpages = webpages

    # Initialize canary counter
    app.state.counter = config.canary_token_tries

    # Start scheduled tasks
    tasks_master = get_tasksmaster()
    tasks_master.run_scheduled_tasks()

    password_line = ""
    if config.dashboard_password_generated:
        password_line = (
            f"\n\nDASHBOARD PASSWORD (auto-generated)\n{config.dashboard_password}"
        )

    banner = f"""

============================================================
DASHBOARD AVAILABLE AT
{config.dashboard_secret_path}{password_line}
============================================================
    """
    app_logger.info(banner)
    app_logger.info(f"Running in {config.mode} mode")
    app_logger.info(f"Starting deception server on port {config.port}...")
    if config.canary_token_url:
        app_logger.info(
            f"Canary token will appear after {config.canary_token_tries} tries"
        )
    else:
        app_logger.info("No canary token configured (set CANARY_TOKEN_URL to enable)")

    yield

    # Shutdown
    app_logger.info("Server shutting down...")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    application = FastAPI(
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    # Random server header middleware (innermost — runs last on request, first on response)
    @application.middleware("http")
    async def server_header_middleware(request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["Server"] = random_server_header()
        return response

    # Deception detection middleware (path traversal, XXE, command injection)
    from middleware.deception import DeceptionMiddleware

    application.add_middleware(DeceptionMiddleware)

    # Banned IP check middleware
    from middleware.ban_check import BanCheckMiddleware

    application.add_middleware(BanCheckMiddleware)

    # Access log middleware (outermost — logs every request with real client IP)
    @application.middleware("http")
    async def access_log_middleware(request: Request, call_next):
        from dependencies import get_client_ip

        response: Response = await call_next(request)

        # Banned requests are already logged by BanCheckMiddleware
        if getattr(request.state, "banned", False):
            return response

        client_ip = get_client_ip(request)
        path = request.url.path
        method = request.method
        status = response.status_code
        access_logger = get_access_logger()

        user_agent = request.headers.get("User-Agent", "")
        tracker = request.app.state.tracker
        suspicious = tracker.is_suspicious_user_agent(user_agent)

        if suspicious:
            access_logger.warning(
                f"[SUSPICIOUS] [{method}] {client_ip} - {path} - {status} - {user_agent[:50]}"
            )
        else:
            access_logger.info(f"[{method}] {client_ip} - {path} - {status}")
        return response

    # Mount static files for the dashboard
    config = get_config()
    secret = config.dashboard_secret_path.lstrip("/")
    static_dir = os.path.join(os.path.dirname(__file__), "templates", "static")
    application.mount(
        f"/{secret}/static",
        StaticFiles(directory=static_dir),
        name="dashboard-static",
    )

    # Import and include routers
    from routes.honeypot import router as honeypot_router
    from routes.api import router as api_router
    from routes.dashboard import router as dashboard_router
    from routes.htmx import router as htmx_router

    # Dashboard/API/HTMX routes (prefixed with secret path, before honeypot catch-all)
    dashboard_prefix = f"/{secret}"
    application.include_router(dashboard_router, prefix=dashboard_prefix)
    application.include_router(api_router, prefix=dashboard_prefix)
    application.include_router(htmx_router, prefix=dashboard_prefix)

    # Honeypot routes (catch-all must be last)
    application.include_router(honeypot_router)

    return application


app = create_app()
