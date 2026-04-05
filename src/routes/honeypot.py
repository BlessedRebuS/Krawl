#!/usr/bin/env python3

"""
Honeypot trap routes for the Krawl deception server.
Migrated from handler.py serve_special_path(), do_POST(), and do_GET() catch-all.
"""

import asyncio
import random
import time
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote_plus

from fastapi import APIRouter, Request, Response, Depends
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse

from dependencies import (
    get_tracker,
    get_app_config,
    get_client_ip,
    build_raw_request,
)
from config import Config
from tracker import AccessTracker
from templates import html_templates
from generators import (
    credentials_txt,
    passwords_txt,
    users_json,
    api_keys_json,
    api_response,
    directory_listing,
)
from deception_responses import (
    generate_sql_error_response,
    get_sql_response_with_data,
    detect_xss_pattern,
    generate_xss_response,
    generate_server_error,
)
from generative_ai import (
    should_use_ai_for_path,
    generate_html_for_path,
    get_model,
    get_provider,
)
from wordlists import get_wordlists
from logger import get_app_logger, get_access_logger, get_credential_logger


async def _safe_body(request: Request) -> str:
    """Read request body, returning empty string on client disconnect."""
    try:
        body_bytes = await request.body()
        return body_bytes.decode("utf-8", errors="replace")
    except Exception:
        return ""


# --- Auto-tracking dependency ---
# Records requests that match attack patterns or honeypot trap paths.


async def _track_honeypot_request(request: Request):
    """Record access for requests with attack patterns or honeypot path hits."""
    tracker = request.app.state.tracker
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "")
    path = request.url.path
    get_app_logger().debug(f"[HoneypotDep] {request.method} {path} from {client_ip}")

    body = ""
    if request.method in ("POST", "PUT"):
        body = await _safe_body(request)

    # Check attack patterns in path and body
    attack_findings = tracker.detect_attack_type(path)

    if body:
        import urllib.parse

        decoded_body = urllib.parse.unquote(body)
        attack_findings.extend(tracker.detect_attack_type(decoded_body))

    # Record if attack pattern detected OR path is a honeypot trap
    if attack_findings or tracker.is_honeypot_path(path):
        import asyncio

        await asyncio.to_thread(
            tracker.record_access,
            ip=client_ip,
            path=path,
            user_agent=user_agent,
            body=body,
            method=request.method,
            raw_request=build_raw_request(request, body),
        )


router = APIRouter(dependencies=[Depends(_track_honeypot_request)])


# --- Helper functions ---


def _should_return_error(config: Config) -> bool:
    if config.probability_error_codes <= 0:
        return False
    return random.randint(1, 100) <= config.probability_error_codes


def _get_random_error_code() -> int:
    wl = get_wordlists()
    error_codes = wl.error_codes
    if not error_codes:
        error_codes = [400, 401, 403, 404, 500, 502, 503]
    return random.choice(error_codes)


# --- HEAD ---


@router.head("/{path:path}")
async def handle_head(path: str):
    return Response(status_code=200, headers={"Content-Type": "text/html"})


# --- POST routes ---


@router.post("/api/search")
@router.post("/api/sql")
@router.post("/api/database")
async def sql_endpoint_post(request: Request):
    client_ip = get_client_ip(request)
    access_logger = get_access_logger()

    post_data = await _safe_body(request)

    base_path = request.url.path
    access_logger.info(
        f"[SQL ENDPOINT POST] {client_ip} - {base_path} - Data: {post_data[:100] if post_data else 'empty'}"
    )

    error_msg, content_type, status_code = generate_sql_error_response(post_data)

    if error_msg:
        access_logger.warning(
            f"[SQL INJECTION DETECTED POST] {client_ip} - {base_path}"
        )
        return Response(
            content=error_msg, status_code=status_code, media_type=content_type
        )
    else:
        response_data = get_sql_response_with_data(base_path, post_data)
        return Response(
            content=response_data, status_code=200, media_type="application/json"
        )


@router.post("/api/contact")
async def contact_post(request: Request):
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "")
    tracker = request.app.state.tracker
    access_logger = get_access_logger()
    app_logger = get_app_logger()

    post_data = await _safe_body(request)

    parsed_data = {}
    if post_data:
        parsed_qs = parse_qs(post_data)
        parsed_data = {k: v[0] if v else "" for k, v in parsed_qs.items()}

    xss_detected = any(detect_xss_pattern(str(v)) for v in parsed_data.values())

    if xss_detected:
        access_logger.warning(
            f"[XSS ATTEMPT DETECTED] {client_ip} - {request.url.path} - Data: {post_data[:200]}"
        )
    else:
        access_logger.info(f"[XSS ENDPOINT POST] {client_ip} - {request.url.path}")

    response_html = generate_xss_response(parsed_data)
    return HTMLResponse(content=response_html, status_code=200)


@router.post("/{path:path}")
async def credential_capture_post(request: Request, path: str):
    """Catch-all POST handler for credential capture."""
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "")
    tracker = request.app.state.tracker
    access_logger = get_access_logger()
    credential_logger = get_credential_logger()

    post_data = await _safe_body(request)

    full_path = f"/{path}"

    access_logger.warning(
        f"[LOGIN ATTEMPT] {client_ip} - {full_path} - {user_agent[:50]}"
    )

    if post_data:
        access_logger.warning(f"[POST DATA] {post_data[:200]}")

        username, password = tracker.parse_credentials(post_data)
        if username or password:
            timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
            credential_line = f"{timestamp}|{client_ip}|{username or 'N/A'}|{password or 'N/A'}|{full_path}"
            credential_logger.info(credential_line)

            await asyncio.to_thread(
                tracker.record_credential_attempt,
                client_ip,
                full_path,
                username or "N/A",
                password or "N/A",
            )

            access_logger.warning(
                f"[CREDENTIALS CAPTURED] {client_ip} - Username: {username or 'N/A'} - Path: {full_path}"
            )

    await asyncio.sleep(1)
    return HTMLResponse(content=html_templates.login_error(), status_code=200)


# --- GET special paths ---


@router.get("/robots.txt")
async def robots_txt():
    return PlainTextResponse(html_templates.robots_txt())


@router.get("/credentials.txt")
async def fake_credentials():
    return PlainTextResponse(credentials_txt())


@router.get("/passwords.txt")
@router.get("/admin_notes.txt")
async def fake_passwords():
    return PlainTextResponse(passwords_txt())


@router.get("/users.json")
async def fake_users_json():
    return JSONResponse(content=None, status_code=200, media_type="application/json")


@router.get("/api_keys.json")
async def fake_api_keys():
    return Response(
        content=api_keys_json(), status_code=200, media_type="application/json"
    )


@router.get("/config.json")
async def fake_config_json():
    return Response(
        content=api_response("/api/config"),
        status_code=200,
        media_type="application/json",
    )


# Override the generic /users.json to return actual content
@router.get("/users.json", include_in_schema=False)
async def fake_users_json_content():
    return Response(
        content=users_json(), status_code=200, media_type="application/json"
    )


@router.get("/admin")
@router.get("/admin/")
@router.get("/admin/login")
@router.get("/login")
async def fake_login():
    return HTMLResponse(html_templates.login_form())


@router.get("/users")
@router.get("/user")
@router.get("/database")
@router.get("/db")
@router.get("/search")
async def fake_product_search():
    return HTMLResponse(html_templates.product_search())


@router.get("/info")
@router.get("/input")
@router.get("/contact")
@router.get("/feedback")
@router.get("/comment")
async def fake_input_form():
    return HTMLResponse(html_templates.input_form())


@router.get("/server")
async def fake_server_error():
    error_html, content_type = generate_server_error()
    return Response(content=error_html, status_code=500, media_type=content_type)


@router.get("/wp-login.php")
@router.get("/wp-login")
@router.get("/wp-admin")
@router.get("/wp-admin/")
async def fake_wp_login():
    return HTMLResponse(html_templates.wp_login())


@router.get("/wp-content/{path:path}")
@router.get("/wp-includes/{path:path}")
async def fake_wordpress(path: str = ""):
    return HTMLResponse(html_templates.wordpress())


@router.get("/phpmyadmin")
@router.get("/phpmyadmin/{path:path}")
@router.get("/phpMyAdmin")
@router.get("/phpMyAdmin/{path:path}")
@router.get("/pma")
@router.get("/pma/")
async def fake_phpmyadmin(path: str = ""):
    return HTMLResponse(html_templates.phpmyadmin())


@router.get("/.env")
async def fake_env():
    return Response(
        content=api_response("/.env"), status_code=200, media_type="application/json"
    )


@router.get("/backup/")
@router.get("/uploads/")
@router.get("/private/")
@router.get("/config/")
@router.get("/database/")
async def fake_directory_listing(request: Request):
    return HTMLResponse(directory_listing(request.url.path))


# --- SQL injection honeypot GET endpoints ---


@router.get("/api/search")
@router.get("/api/sql")
@router.get("/api/database")
async def sql_endpoint_get(request: Request):
    client_ip = get_client_ip(request)
    access_logger = get_access_logger()
    app_logger = get_app_logger()

    base_path = request.url.path
    request_query = request.url.query or ""

    error_msg, content_type, status_code = generate_sql_error_response(request_query)

    if error_msg:
        access_logger.warning(
            f"[SQL INJECTION DETECTED] {client_ip} - {base_path} - Query: {request_query[:100] if request_query else 'empty'}"
        )
        return Response(
            content=error_msg, status_code=status_code, media_type=content_type
        )
    else:
        access_logger.info(
            f"[SQL ENDPOINT] {client_ip} - {base_path} - Query: {request_query[:100] if request_query else 'empty'}"
        )
        response_data = get_sql_response_with_data(base_path, request_query)
        return Response(
            content=response_data, status_code=200, media_type="application/json"
        )


# --- Generic /api/* fake endpoints ---


@router.get("/api/{path:path}")
async def fake_api_catchall(request: Request, path: str):
    full_path = f"/api/{path}"
    return Response(
        content=api_response(full_path), status_code=200, media_type="application/json"
    )


# --- Catch-all GET (trap pages with random links) ---
# This MUST be registered last in the router


@router.get("/{path:path}")
async def trap_page(request: Request, path: str):
    """Generate trap page with random links. This is the catch-all route."""
    config = request.app.state.config
    tracker = request.app.state.tracker
    app_logger = get_app_logger()
    access_logger = get_access_logger()

    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "")
    full_path = f"/{path}" if path else "/"

    app_logger.debug(f"[TrapPage] {client_ip} - {full_path}")

    # Check wordpress-like paths
    if "wordpress" in full_path.lower():
        return HTMLResponse(html_templates.wordpress())

    is_suspicious = tracker.is_suspicious_user_agent(user_agent)

    # Record access + increment page visit in a single DB transaction.
    # Skip if the router dependency already recorded this request
    # (attack pattern or honeypot path → already recorded by _track_honeypot_request).
    if not tracker.detect_attack_type(full_path) and not tracker.is_honeypot_path(
        full_path
    ):
        current_visit_count = await asyncio.to_thread(
            tracker.record_access,
            ip=client_ip,
            path=full_path,
            user_agent=user_agent,
            method=request.method,
            raw_request=build_raw_request(request) if is_suspicious else "",
            increment_page_visit=True,
        )
    else:
        # Already recorded by dependency; still need page visit count
        current_visit_count = await asyncio.to_thread(
            tracker.increment_page_visit, client_ip
        )

    # Random error response
    if _should_return_error(config):
        error_code = _get_random_error_code()
        access_logger.info(f"Returning error {error_code} to {client_ip} - {full_path}")
        return Response(status_code=error_code)

    # Try AI generation for paths not in robots.txt
    if should_use_ai_for_path(full_path):
        try:
            (
                html_content,
                content_type,
                status_code,
                was_cached,
            ) = await generate_html_for_path(full_path, request.url.query or "")
            model = get_model()
            provider = get_provider()
            cache_flag = "[CACHED]" if was_cached else ""
            if cache_flag:
                access_logger.info(
                    f"[AI GENERATED] {cache_flag} {client_ip} - {full_path} - {provider}/{model}"
                )
            else:
                access_logger.info(
                    f"[AI GENERATED] {client_ip} - {full_path} - {provider}/{model}"
                )
            return HTMLResponse(content=html_content, status_code=status_code)
        except Exception as err:
            app_logger.warning(
                f"AI generation failed for {full_path}, falling back to default: {err}"
            )

    # Response delay
    await asyncio.sleep(config.delay / 1000.0)

    # Tarpit: artificially slow down responses to trap AI crawlers
    if config.tarpit_enabled:
        await asyncio.sleep(config.tarpit_delay_seconds)

    # Generate page (sync function with DB calls, run in thread)
    page_html = await asyncio.to_thread(
        _generate_page,
        config,
        tracker,
        client_ip,
        full_path,
        current_visit_count,
        request.app,
    )

    # Decrement canary counter
    request.app.state.counter -= 1
    if request.app.state.counter < 0:
        request.app.state.counter = config.canary_token_tries

    return HTMLResponse(content=page_html, status_code=200)


_TARPIT_WORDS = [
    "the",
    "be",
    "to",
    "of",
    "and",
    "a",
    "in",
    "that",
    "have",
    "it",
    "for",
    "not",
    "on",
    "with",
    "as",
    "you",
    "do",
    "at",
    "this",
    "but",
    "his",
    "by",
    "from",
    "they",
    "we",
    "say",
    "her",
    "she",
    "or",
    "an",
    "will",
    "my",
    "one",
    "all",
    "would",
    "there",
    "their",
    "what",
    "so",
    "up",
    "out",
    "if",
    "about",
    "who",
    "get",
    "which",
    "go",
    "me",
    "when",
    "make",
    "can",
    "like",
    "time",
    "no",
    "just",
    "him",
    "know",
    "take",
    "people",
    "into",
    "year",
    "your",
    "good",
    "some",
    "could",
    "them",
    "see",
    "other",
    "than",
    "then",
    "now",
    "look",
    "only",
    "come",
    "its",
    "over",
    "think",
    "also",
    "back",
    "after",
    "use",
    "two",
    "how",
    "our",
    "work",
    "first",
    "well",
    "way",
    "even",
    "new",
    "want",
    "because",
    "any",
    "these",
    "give",
    "day",
    "most",
    "us",
    "great",
]


def _tarpit_text(n_words: int = 60) -> str:
    """Generate random word salad to confuse AI training data scrapers."""
    return " ".join(random.choice(_TARPIT_WORDS) for _ in range(n_words))


def _generate_page(config, tracker, client_ip, seed, page_visit_count, app) -> str:
    """Generate a webpage containing random links or canary token."""
    random.seed(seed)

    ip_category = tracker.get_category_by_ip(client_ip)

    should_apply_crawler_limit = False
    if config.infinite_pages_for_malicious:
        if (
            ip_category == "good_crawler" or ip_category == "regular_user"
        ) and page_visit_count >= config.max_pages_limit:
            should_apply_crawler_limit = True
    else:
        if (
            ip_category == "good_crawler"
            or ip_category == "bad_crawler"
            or ip_category == "attacker"
        ) and page_visit_count >= config.max_pages_limit:
            should_apply_crawler_limit = True

    if should_apply_crawler_limit:
        return html_templates.main_page(
            app.state.counter, "<p>Crawl limit reached.</p>"
        )

    num_pages = random.randint(*config.links_per_page_range)
    content = ""

    if app.state.counter <= 0 and config.canary_token_url:
        content += f"""
        <div class="link-box canary-token">
            <a href="{config.canary_token_url}">{config.canary_token_url}</a>
        </div>
"""

    webpages = app.state.webpages
    if webpages is None:
        for _ in range(num_pages):
            address = "".join(
                [
                    random.choice(config.char_space)
                    for _ in range(random.randint(*config.links_length_range))
                ]
            )
            content += f"""
        <div class="link-box">
            <a href="{address}">{address}</a>
        </div>
"""
    else:
        for _ in range(num_pages):
            address = random.choice(webpages)
            content += f"""
        <div class="link-box">
            <a href="{address}">{address}</a>
        </div>
"""

    if config.tarpit_enabled:
        content += f"""
        <div class="link-box tarpit-text" style="max-width:800px;text-align:left;font-size:13px;color:#8b949e;">
            <p>{_tarpit_text()}</p>
        </div>
"""

    return html_templates.main_page(app.state.counter, content)
