#!/usr/bin/env python3

"""
FastAPI application factory for the Krawl honeypot.
Replaces the old http.server-based server.py.
"""

import sys
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles

from config import get_config
from tracker import AccessTracker, set_tracker
from database import initialize_database
from tasks_master import get_tasksmaster
from logger import initialize_logging, get_app_logger
from generators import random_server_header


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    config = get_config()

    # Initialize logging
    initialize_logging(log_level=config.log_level)
    app_logger = get_app_logger()

    # Initialize database and run pending migrations before accepting traffic
    try:
        app_logger.info(f"Initializing database at: {config.database_path}")
        initialize_database(config.database_path)
        app_logger.info("Database ready")
    except Exception as e:
        app_logger.warning(
            f"Database initialization failed: {e}. Continuing with in-memory only."
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

    banner = f"""

============================================================
DASHBOARD AVAILABLE AT
{config.dashboard_secret_path}
============================================================
    """
    app_logger.info(banner)
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

    # Banned IP check middleware (outermost — runs first on request)
    from middleware.ban_check import BanCheckMiddleware

    application.add_middleware(BanCheckMiddleware)

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
