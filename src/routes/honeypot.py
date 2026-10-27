#!/usr/bin/env python3

"""
Honeypot routes: bait pages from the response catalogue, credential capture for
every POST/PUT, and the trap maze for every other GET.
"""

import asyncio
import random
from datetime import datetime

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse

from config import Config, get_config
from dependencies import (
    build_raw_request,
    get_client_ip,
    read_body_capped,
)
from detection import get_response_catalog
from generative_ai import (
    generate_html_for_path,
    get_model,
    get_provider,
    should_use_ai_for_path,
)
from logger import get_access_logger, get_app_logger, get_credential_logger
from templates import main_page


async def _safe_body(request: Request) -> str:
    """Read the request body, bounded, empty on client disconnect."""
    return (await read_body_capped(request)).decode("utf-8", errors="replace")


# --- Auto-tracking dependency ---
# Records requests that match attack patterns or honeypot trap paths.


async def _track_honeypot_request(request: Request):
    """Record attacks, honeypot hits, and bounded file uploads."""
    tracker = request.app.state.tracker
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "")
    referer = request.headers.get("Referer", "") if get_config().referer_enabled else ""
    target_host = request.headers.get("Host", "")
    path = request.url.path
    query = request.url.query or ""
    get_app_logger().debug(f"[HoneypotDep] {request.method} {path} from {client_ip}")

    body_bytes = b""
    body = ""
    if request.method in ("POST", "PUT"):
        body_bytes = await read_body_capped(request)
        body = body_bytes.decode("utf-8", errors="replace")

    # Reuse the DeceptionMiddleware scan when it ran; scan here otherwise. The
    # last fallback keeps lightweight third-party tracker doubles compatible.
    detection_findings = getattr(request.state, "detection_findings", None)
    if detection_findings is None and hasattr(tracker, "detector"):
        detection_findings = tracker.detector.scan_request(
            path=path,
            query=query,
            body=body,
            user_agent=user_agent,
            method=request.method,
            headers=request.headers.items(),
        )
    if detection_findings is not None:
        attack_findings = [
            item for item in detection_findings if item.classification == "attack"
        ]
    else:
        attack_findings = tracker.detect_attack_type(path)

    # File capture is independent of attack matching and TLSH. Hashing is the
    # optional part; exact SHA-256 metadata is still retained when TLSH is off.
    file_payloads = []
    if body_bytes:
        from tlsh_utils import extract_file_payloads_from_body

        file_payloads = extract_file_payloads_from_body(
            body_bytes,
            request.headers.get("Content-Type", ""),
            compute_tlsh=get_config().tlsh_enabled,
            filename_hint=path.rstrip("/").rsplit("/", 1)[-1],
        )

    # A real upload is evidence in its own right, even when neither its path nor
    # its content happens to match an attack signature.
    if attack_findings or tracker.is_honeypot_path(path) or file_payloads:
        import asyncio

        raw_request = build_raw_request(request, body)

        await asyncio.to_thread(
            tracker.record_access,
            ip=client_ip,
            path=path,
            user_agent=user_agent,
            body=body,
            query=query,
            method=request.method,
            raw_request=raw_request,
            referer=referer,
            file_payloads=file_payloads,
            target_host=target_host,
            detection_findings=detection_findings,
        )
        # Route handlers read this instead of re-deriving the decision above.
        request.state.access_recorded = True


router = APIRouter(dependencies=[Depends(_track_honeypot_request)])


# --- Helper functions ---


def _should_return_error(config: Config) -> bool:
    if config.probability_error_codes <= 0:
        return False
    return random.randint(1, 100) <= config.probability_error_codes


def _get_random_error_code() -> int:
    return random.choice(get_config().error_codes)


def _page_response(request: Request) -> Response | None:
    """The pages: entry for this request from responses/manifest.yaml, if any."""
    reply = get_response_catalog().page(
        request.url.path, request.method, request.url.query or ""
    )
    if reply is None:
        return None
    return Response(
        content=reply.body,
        status_code=reply.status,
        media_type=reply.content_type,
        headers=dict(reply.headers),
    )


# --- POST/PUT: credential capture, then a page or the login_failed reply ---


@router.post("/{path:path}")
@router.put("/{path:path}")
async def credential_capture_post(request: Request, path: str):
    """Catch-all POST/PUT handler for credential and upload capture."""
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
    page = _page_response(request)
    if page is not None:
        return page
    reply = get_response_catalog().login_failed(full_path, request.url.query or "")
    return Response(
        content=reply.body,
        status_code=reply.status,
        media_type=reply.content_type,
        headers=dict(reply.headers),
    )


# --- Catch-all GET/HEAD: a bait page, else the trap maze ---
# This MUST be registered last in the router


@router.api_route("/{path:path}", methods=["GET", "HEAD"])
async def trap_page(request: Request, path: str):
    """Serve the pages: entry for this path, else a trap page with random links."""
    page = _page_response(request)
    if page is not None:
        return page

    config = request.app.state.config
    tracker = request.app.state.tracker
    app_logger = get_app_logger()
    access_logger = get_access_logger()

    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "")
    full_path = f"/{path}" if path else "/"

    app_logger.debug(f"[TrapPage] {client_ip} - {full_path}")

    is_suspicious = tracker.is_suspicious_user_agent(user_agent)

    # Record access + increment page visit in a single DB transaction, unless
    # _track_honeypot_request already recorded this request.
    if not getattr(request.state, "access_recorded", False):
        current_visit_count = await asyncio.to_thread(
            tracker.record_access,
            ip=client_ip,
            path=full_path,
            user_agent=user_agent,
            method=request.method,
            raw_request=build_raw_request(request) if is_suspicious else "",
            target_host=request.headers.get("Host", ""),
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
            ) = await asyncio.shield(
                generate_html_for_path(full_path, request.url.query or "")
            )
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
            # Honour the generated content type: HTMLResponse would stamp
            # text/html on a sourcemap or a .env dump and give the game away.
            return Response(
                content=html_content,
                status_code=status_code,
                media_type=content_type,
            )
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
        return main_page(app.state.counter, "<p>Crawl limit reached.</p>")

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

    return main_page(app.state.counter, content)
