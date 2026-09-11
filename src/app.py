#!/usr/bin/env python3

"""
FastAPI application factory for the Krawl honeypot.
Replaces the old http.server-based server.py.
"""

import gc
import os
import time
from contextlib import asynccontextmanager, contextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from config import get_config
from dashboard_cache import initialize_cache
from database import get_database, initialize_database
from generators import random_server_header
from logger import get_access_logger, get_app_logger, initialize_logging
from routes.dashboard import KRAWL_VERSION
from tasks_master import get_tasksmaster
from tracker import AccessTracker


@contextmanager
def _phase(app_logger, name: str, fatal: bool = False):
    """Log a startup phase with its duration, and never let it stall silently.

    Boot used to run eight hand-rolled try/excepts that only logged on success,
    so a slow phase (the database cleanup, typically) looked like a hang right
    after "Database ready". Now every phase announces itself before it runs.

    Non-fatal phases log the failure and let startup continue, matching the
    previous behaviour; `fatal=True` re-raises.
    """
    app_logger.info(f"→ {name}")
    t0 = time.monotonic()
    try:
        yield
    except Exception as e:
        app_logger.error(f"✗ {name} failed after {time.monotonic() - t0:.1f}s: {e}")
        if fatal:
            raise
    else:
        app_logger.info(f"✓ {name} ({time.monotonic() - t0:.1f}s)")


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
            app_logger.info("Initializing database in scalable mode (PostgreSQL)")
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

    # One-time startup cleanup: purge configured ignored IPs that predate the
    # tracking guard and clear stale (fully expired) ban state.
    with _phase(app_logger, "Database startup cleanup"):
        from database.startup import run_startup_cleanup

        run_startup_cleanup(
            get_database(),
            config.ban_duration_seconds,
            config.ignored_ips,
            purge_ipv6=config.ipv6_ignore and config.ipv6_purge_existing,
        )

    # Initialize cache backend (in-memory dict for standalone, Redis for scalable)
    if config.mode == "scalable":
        # No fallback here on purpose. Falling back to the in-memory backend
        # moves the shared ledgers (first-sighting IPs, distinct paths, auth
        # sessions) into per-process dicts that only Redis bounds — under a
        # flood that is an unbounded memory leak, and it used to happen behind
        # a single WARNING. Failing loudly lets the orchestrator restart us
        # once Redis is actually reachable.
        with _phase(app_logger, "Redis cache init", fatal=True):
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
            app_logger.info(f"Redis at {config.redis_host}:{config.redis_port}")
    else:
        with _phase(app_logger, "In-memory cache init"):
            initialize_cache(mode="standalone")

    # Seed event-driven metric counters (from metrics_summary or a one-time
    # recompute). In scalable mode only the first pod actually seeds.
    with _phase(app_logger, "Metric counter seed"):
        import metrics_counters

        metrics_counters.bootstrap(get_database())

    # Resolve server IP once (used to exclude self-traffic from stats)
    with _phase(app_logger, "Server IP resolution"):
        config.resolve_server_ip()
        if config.get_server_ip():
            app_logger.info(f"Server public IP: {config.get_server_ip()}")
        else:
            app_logger.warning("Server public IP could not be determined")

    # Log AI configuration status
    from generative_ai import (
        get_model,
        get_provider,
        import_deception_pages_from_directory,
        is_ai_enabled,
    )

    if is_ai_enabled():
        provider = get_provider()
        model = get_model()
        app_logger.info(f"AI generation enabled - Provider: {provider}, Model: {model}")
    else:
        app_logger.info(
            "AI generation disabled - Cached AI pages will still be served if available"
        )

    # Import deception pages from templates directory
    with _phase(app_logger, "Deception page import"):
        app_logger.info(f"Imported {import_deception_pages_from_directory()} pages")

    # Initialize tracker
    tracker = AccessTracker(config.max_pages_limit, config.ban_duration_seconds)

    # Initial banlist sync (before accepting traffic)
    if config.banlist_sources:
        with _phase(app_logger, "Initial banlist sync"):
            from banlist_sync import load_published, refresh_banlist_sources

            # A pod joining a running cluster adopts what a peer already
            # fetched; only a cold cluster pays for the external requests.
            if not load_published():
                refresh_banlist_sources()

    # The wordmark is identical on every dashboard page and never changes after
    # startup, so it resolves once into the template env instead of per request.
    from dependencies import build_brand, get_templates
    from routes.dashboard import KRAWL_VERSION

    templates = get_templates()
    templates.env.globals["brand"] = build_brand(config, KRAWL_VERSION)
    # Cache-buster on every static asset. Renaming a CSS class is a breaking
    # change for a stylesheet a proxy still has from the last release, so the
    # URL has to change when the release does.
    templates.env.globals["krawl_version"] = KRAWL_VERSION

    # Store in app.state for dependency injection
    app.state.config = config
    app.state.tracker = tracker

    # Load webpages file if provided via env var
    webpages = None
    webpages_file = os.environ.get("KRAWL_WEBPAGES_FILE")
    if webpages_file:
        try:
            with open(webpages_file) as f:
                webpages = f.readlines()
            if not webpages:
                app_logger.warning(
                    "The webpages file was empty. Using randomly generated links."
                )
                webpages = None
        except OSError:
            app_logger.warning(
                "Can't read webpages file. Using randomly generated links."
            )
    app.state.webpages = webpages

    # Initialize canary counter
    app.state.counter = config.canary_token_tries

    # Start scheduled tasks
    with _phase(app_logger, "Scheduled task startup"):
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
    from generative_ai import close_aiohttp_session

    await close_aiohttp_session()
    app_logger.info("Server shutting down...")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    config = get_config()
    secret = config.dashboard_secret_path.lstrip("/")
    dashboard_prefix = f"/{secret}"

    # Docs live under the secret dashboard path. Only the JSON API router is
    # included in the schema (see include_in_schema=False below), so the spec
    # stays limited to /api/* without post-processing it.
    application = FastAPI(
        title="Krawl Dashboard API",
        version=KRAWL_VERSION,
        description="API endpoints for the Krawl honeypot dashboard.\n\n"
        "Endpoints marked with a lock icon require authentication. "
        "Authenticate via `POST /api/auth` to obtain a session cookie.",
        docs_url=f"{dashboard_prefix}/docs",
        redoc_url=None,
        openapi_url=f"{dashboard_prefix}/openapi.json",
        lifespan=lifespan,
    )

    from routes.api import Unauthorized

    @application.exception_handler(Unauthorized)
    async def unauthorized_handler(request: Request, exc: Unauthorized):
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)

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

        path = request.url.path

        # Don't log health probes — they fire every few seconds and add noise.
        # The probe path is derived from the (possibly auto-generated) secret.
        config = request.app.state.config
        health_path = "/" + config.dashboard_secret_path.lstrip("/") + "/healthz"
        if path == health_path:
            return response

        client_ip = get_client_ip(request)
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

    # Outermost layer: ignored IPs are answered here, from the ASGI scope
    # alone, so nothing below allocates for them. Added last because Starlette
    # wraps in reverse registration order — last added is outermost.
    from middleware.drop_ignored import DropIgnoredMiddleware

    application.add_middleware(
        DropIgnoredMiddleware,
        dashboard_prefix="/" + config.dashboard_secret_path.lstrip("/"),
    )

    # Mount static files for the dashboard
    static_dir = os.path.join(os.path.dirname(__file__), "templates", "static")

    application.mount(
        f"/{secret}/static",
        StaticFiles(directory=static_dir),
        name="dashboard-static",
    )

    # Get the favicon from the data directory. Serve that one if it exists. If not, serve the default one under /templates/static.
    data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")

    @application.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        if os.path.exists(os.path.join(data_dir, "favicon.ico")):
            return FileResponse(os.path.join(data_dir, "favicon.ico"))
        return FileResponse(os.path.join(static_dir, "favicon.ico"))

    # Import and include routers
    from routes.api import router as api_router
    from routes.dashboard import router as dashboard_router
    from routes.honeypot import router as honeypot_router
    from routes.htmx import router as htmx_router

    # Dashboard/API/HTMX routes (prefixed with secret path, before honeypot catch-all)
    application.include_router(
        dashboard_router, prefix=dashboard_prefix, include_in_schema=False
    )
    application.include_router(api_router, prefix=dashboard_prefix)
    application.include_router(
        htmx_router, prefix=dashboard_prefix, include_in_schema=False
    )

    # Public banlist route (before honeypot catch-all, after dashboard)
    if config.banlist_export_path:
        from routes.banlist import public_banlist_handler

        banlist_path = config.banlist_export_path
        if not banlist_path.startswith("/"):
            banlist_path = "/" + banlist_path
        application.add_api_route(
            banlist_path,
            public_banlist_handler,
            methods=["GET"],
            include_in_schema=False,
        )

    # Honeypot routes (catch-all must be last, and never in the API schema)
    application.include_router(honeypot_router, include_in_schema=False)

    return application


app = create_app()
