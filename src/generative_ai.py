#!/usr/bin/env python3

"""
Generative AI module for dynamic honeypot page generation.
Supports both OpenRouter and OpenAI APIs for generating HTML responses.
Caches generated pages in the database to avoid redundant API calls.
"""

import json
import os
import logging
import asyncio
import base64
from typing import Optional, Tuple, List
from pathlib import Path
from datetime import datetime

import aiohttp

logger = logging.getLogger("krawl")

# Cache robots.txt disallowed paths
_robots_disallowed_cache: Optional[List[str]] = None


def is_ai_enabled() -> bool:
    """Check if AI generation is enabled via config or environment variable."""
    from config import get_config

    config = get_config()
    return config.ai_enabled


def get_api_key() -> Optional[str]:
    """Get OpenRouter API key from config or environment."""
    from config import get_config

    config = get_config()
    # Env var takes precedence over config file
    return os.getenv("OPENROUTER_API_KEY") or config.ai_api_key


def get_model() -> str:
    """Get OpenRouter model from config or environment."""
    from config import get_config

    config = get_config()
    # Env var takes precedence over config file
    return os.getenv("OPENROUTER_MODEL") or config.ai_model


def get_prompt() -> str:
    """Get custom prompt template from config."""
    from config import get_config

    config = get_config()
    return config.ai_prompt


def get_timeout() -> int:
    """Get API request timeout from config."""
    from config import get_config

    config = get_config()
    return config.ai_timeout


def get_provider() -> str:
    """Get AI provider ('openrouter' or 'openai') from config."""
    from config import get_config

    config = get_config()
    provider = config.ai_provider.lower()
    if provider not in ("openrouter", "openai"):
        logger.warning(f"Invalid provider '{provider}', defaulting to openrouter")
        return "openrouter"
    return provider


def get_max_daily_requests() -> int:
    """Get max daily AI requests limit from config."""
    from config import get_config

    config = get_config()
    return config.ai_max_daily_requests


def can_generate_today() -> bool:
    """Check if we can still generate more pages today based on daily limit."""
    from dependencies import get_db
    from datetime import date

    max_requests = get_max_daily_requests()
    if max_requests <= 0:  # No limit if set to 0 or negative
        return True

    db = get_db()
    today = date.today()

    # Count generated pages created today
    generated_today = db.count_generated_pages_created_today()

    if generated_today >= max_requests:
        logger.warning(
            f"Daily AI generation limit reached: {generated_today}/{max_requests} pages already generated today"
        )
        return False

    return True


def load_robots_disallowed() -> List[str]:
    """Load and parse robots.txt to get disallowed paths.

    Returns:
        List of disallowed paths from robots.txt
    """
    global _robots_disallowed_cache

    if _robots_disallowed_cache is not None:
        return _robots_disallowed_cache

    disallowed_paths = []

    # Try to find robots.txt in templates/html directory
    robots_paths = [
        Path(__file__).parent / "templates" / "html" / "robots.txt",
        Path(__file__).parent / "templates" / "robots.txt",
        Path(__file__).parent / "robots.txt",
    ]

    for robots_file in robots_paths:
        if robots_file.exists():
            try:
                with open(robots_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("Disallow:"):
                            path = line.replace("Disallow:", "").strip()
                            if path:
                                disallowed_paths.append(path)

                logger.debug(
                    f"Loaded {len(disallowed_paths)} disallowed paths from {robots_file}"
                )
                _robots_disallowed_cache = disallowed_paths
                return disallowed_paths
            except Exception as err:
                logger.warning(f"Failed to load robots.txt from {robots_file}: {err}")

    logger.warning("robots.txt not found, no paths will be blocked")
    _robots_disallowed_cache = []
    return []


def get_generated_page_from_db(path: str) -> Optional[str]:
    """Retrieve a cached generated page from database.

    Args:
        path: Request path

    Returns:
        HTML content (decoded from base64) or None if not found
    """
    try:
        from database import DatabaseManager
        from models import GeneratedPage

        db = DatabaseManager()
        session = db.session

        page = session.query(GeneratedPage).filter(GeneratedPage.path == path).first()

        if page:
            # Update last_accessed and increment access count
            page.last_accessed = datetime.utcnow()
            page.access_count = (page.access_count or 0) + 1
            session.commit()

            # Decode base64 HTML content
            html_content = base64.b64decode(page.html_content_b64).decode("utf-8")
            logger.debug(
                f"Retrieved generated page from DB for path: {path} (accesses: {page.access_count})"
            )
            return html_content

        return None
    except Exception as err:
        logger.warning(f"Failed to retrieve generated page from DB for {path}: {err}")
        return None


def save_generated_page_to_db(path: str, html_content: str) -> bool:
    """Save a generated page to database with base64 encoding.

    Args:
        path: Request path
        html_content: HTML content to store

    Returns:
        True if saved successfully, False otherwise
    """
    try:
        from database import DatabaseManager
        from models import GeneratedPage

        db = DatabaseManager()
        session = db.session

        # Encode HTML content to base64
        html_b64 = base64.b64encode(html_content.encode("utf-8")).decode("utf-8")

        # Check if path already exists (upsert)
        existing_page = (
            session.query(GeneratedPage).filter(GeneratedPage.path == path).first()
        )

        if existing_page:
            # Update existing entry
            existing_page.html_content_b64 = html_b64
            existing_page.last_accessed = datetime.utcnow()
            logger.debug(f"Updated generated page in DB for path: {path}")
        else:
            # Create new entry
            new_page = GeneratedPage(
                path=path,
                html_content_b64=html_b64,
                created_at=datetime.utcnow(),
                last_accessed=datetime.utcnow(),
                access_count=0,
            )
            session.add(new_page)
            logger.debug(f"Saved new generated page to DB for path: {path}")

        session.commit()
        return True
    except Exception as err:
        logger.error(f"Failed to save generated page to DB for {path}: {err}")
        return False


async def call_openrouter(
    api_key: str,
    model: str,
    prompt: str,
    timeout: int = 30,
) -> str:
    """Call OpenRouter API asynchronously and return the response.

    Args:
        api_key: OpenRouter API key
        model: Model name to use
        prompt: Prompt to send to the API
        timeout: Request timeout in seconds

    Returns:
        Response content from the API

    Raises:
        RuntimeError: If API call fails
    """
    return await _call_api(
        url="https://openrouter.ai/api/v1/chat/completions",
        api_key=api_key,
        model=model,
        prompt=prompt,
        timeout=timeout,
        provider="OpenRouter",
    )


async def call_openai(
    api_key: str,
    model: str,
    prompt: str,
    timeout: int = 30,
) -> str:
    """Call OpenAI API asynchronously and return the response.

    Args:
        api_key: OpenAI API key
        model: Model name to use (e.g., "gpt-4", "gpt-3.5-turbo")
        prompt: Prompt to send to the API
        timeout: Request timeout in seconds

    Returns:
        Response content from the API

    Raises:
        RuntimeError: If API call fails
    """
    return await _call_api(
        url="https://api.openai.com/v1/chat/completions",
        api_key=api_key,
        model=model,
        prompt=prompt,
        timeout=timeout,
        provider="OpenAI",
    )


async def _call_api(
    url: str,
    api_key: str,
    model: str,
    prompt: str,
    timeout: int,
    provider: str,
) -> str:
    """Generic API call handler for both OpenRouter and OpenAI.

    Args:
        url: API endpoint URL
        api_key: API key
        model: Model name
        prompt: Prompt text
        timeout: Request timeout
        provider: Provider name for logging

    Returns:
        Response content

    Raises:
        RuntimeError: If API call fails
    """
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You are a realistic honeypot server that generates plausible but fake HTML pages. Generate only HTML content, no markdown or explanation.",
            },
            {"role": "user", "content": prompt},
        ],
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    site_url = os.getenv("OPENROUTER_SITE_URL") or os.getenv("OPENAI_SITE_URL")
    app_name = (
        os.getenv("OPENROUTER_APP_NAME")
        or os.getenv("OPENAI_APP_NAME")
        or "Krawl Honeypot"
    )
    if site_url:
        headers["HTTP-Referer"] = site_url
    if app_name:
        headers["X-Title"] = app_name

    timeout_obj = aiohttp.ClientTimeout(total=timeout)

    try:
        async with aiohttp.ClientSession(timeout=timeout_obj) as session:
            async with session.post(
                url,
                json=payload,
                headers=headers,
            ) as response:
                if response.status != 200:
                    error_body = await response.text()
                    raise RuntimeError(
                        f"{provider} HTTP {response.status}: {error_body}"
                    )
                body = await response.json()
    except aiohttp.ClientError as err:
        raise RuntimeError(f"{provider} network error: {err}") from err
    except asyncio.TimeoutError as err:
        raise RuntimeError(f"{provider} request timeout: {err}") from err
    except Exception as err:
        raise RuntimeError(f"{provider} request failed: {err}") from err

    try:
        return body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as err:
        raise RuntimeError(f"{provider} unexpected response: {body}") from err


async def generate_html_for_path(
    path: str, query: str = ""
) -> Tuple[str, str, int, bool]:
    """Generate HTML response for a given path using AI asynchronously.

    Checks the database cache first. If found, returns cached page regardless of AI enabled status.
    If not found and AI is enabled, calls AI to generate and stores the result.
    If not found and AI is disabled, raises RuntimeError to trigger fallback.

    Args:
        path: Request path (e.g., "/some/page")
        query: Query string (e.g., "param=value")

    Returns:
        Tuple of (html_content, content_type, status_code, was_cached)
        where was_cached is True if served from database cache, False if freshly generated
    """
    # ALWAYS check database cache first - serve cached pages even if AI is disabled
    cached_html = get_generated_page_from_db(path)
    if cached_html:
        logger.debug(
            f"[DB CACHE HIT] Retrieved cached AI-generated page for path: {path}"
        )
        return (cached_html, "text/html", 200, True)

    # No cached page - check if we can generate new ones
    if not is_ai_enabled():
        logger.debug(f"AI generation is disabled and no cached page for {path}")
        raise RuntimeError("AI generation is disabled and no cached page found")

    # Check daily generation limit
    if not can_generate_today():
        logger.warning(
            f"Daily AI generation limit reached, falling back to default honeypot behavior for path: {path}"
        )
        raise RuntimeError(f"Daily AI generation limit reached")

    api_key = get_api_key()
    if not api_key:
        logger.warning(
            "OpenRouter API key not set in config or OPENROUTER_API_KEY env var, AI generation disabled"
        )
        return (
            "<html><body><h1>404 Not Found</h1></body></html>",
            "text/html",
            404,
            False,
        )

    model = get_model()
    provider = get_provider()

    # Build prompt for AI
    query_part = f"?{query}" if query else ""
    prompt_template = get_prompt()
    prompt = prompt_template.format(path=path, query_part=query_part)
    timeout = get_timeout()

    try:
        logger.debug(
            f"[AI GENERATION] Generating response for path: {path} with {provider} (timeout: {timeout}s)"
        )
        logger.debug(f"Using model: {model}")
        logger.debug(f"Using prompt: {prompt[:100]}...")

        if provider == "openai":
            html_content = await call_openai(
                api_key=api_key, model=model, prompt=prompt, timeout=timeout
            )
        else:  # openrouter
            html_content = await call_openrouter(
                api_key=api_key, model=model, prompt=prompt, timeout=timeout
            )

        # Strip markdown code blocks if present (common LLM behavior)
        html_content = html_content.strip()
        if html_content.startswith("```"):
            # Remove opening code block (e.g., ```html or ```)
            lines = html_content.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            html_content = "\n".join(lines).strip()

        logger.debug(f"Cleaned HTML response (first 200 chars): {html_content[:200]}")

        # Ensure we have valid HTML
        if not html_content.startswith("<"):
            logger.warning(
                f"AI response not HTML-formatted for path {path}, wrapping content"
            )
            html_content = f"<html><body>{html_content}</body></html>"

        logger.debug(f"Final HTML length: {len(html_content)}")

        # Save generated page to database cache
        if save_generated_page_to_db(path, html_content):
            logger.debug(f"[DB CACHE SAVE] Saved generated page for path: {path}")

        return (html_content, "text/html", 200, False)

    except RuntimeError as err:
        logger.error(f"AI generation failed for path {path}: {err}")
        return (
            "<html><body><h1>500 Internal Server Error</h1></body></html>",
            "text/html",
            500,
            False,
        )
    except Exception as err:
        logger.error(f"Unexpected error in AI generation for path {path}: {err}")
        return (
            "<html><body><h1>500 Internal Server Error</h1></body></html>",
            "text/html",
            500,
            False,
        )


def should_use_ai_for_path(path: str) -> bool:
    """Determine if AI generation should be used for a path.

    This returns True if:
    - AI is enabled AND path meets criteria (not root, not dashboard, not in robots.txt, etc.)
    - OR there's a cached AI-generated page for this path (even if AI is currently disabled)

    Args:
        path: Request path

    Returns:
        True if path should try to use AI (for generation or cached retrieval)
    """
    # Check if there's a cached page even if AI is disabled
    cached_page = get_generated_page_from_db(path)
    if cached_page:
        logger.debug(f"Found cached AI page for {path}, will serve it")
        return True

    if not is_ai_enabled():
        return False

    # Exclude root path
    if path == "/" or path == "":
        return False

    # Exclude dashboard paths
    try:
        from config import get_config

        config = get_config()
        dashboard_path = "/" + config.dashboard_secret_path.lstrip("/")
        if path.startswith(dashboard_path):
            return False
    except Exception:
        pass  # If config fails, continue with other checks

    # Exclude randomly generated links from homepage
    if _is_random_link(path):
        return False

    # Load robots.txt disallowed paths
    robots_disallowed_paths = load_robots_disallowed()

    # Check if path exactly matches a robots.txt disallowed path
    # Only exclude exact matches, not sub-paths (e.g., /wp-admin is excluded,
    # but /wp-admin/test.php queries AI since the hit is not precise)
    for disallowed in robots_disallowed_paths:
        if path == disallowed:
            return False

    return True


def _is_random_link(path: str) -> bool:
    """Check if path is a randomly generated link from the homepage.

    Random links are single-segment paths with characters from char_space
    and length within the configured range.

    Args:
        path: Request path

    Returns:
        True if path matches random link pattern
    """
    from config import get_config

    config = get_config()
    char_space = config.char_space
    min_len, max_len = config.links_length_range

    # Remove leading slash
    link_name = path.lstrip("/")

    # Check if it's a single segment (no slashes)
    if "/" in link_name or not link_name:
        return False

    # Check length is within range
    if not (min_len <= len(link_name) <= max_len):
        return False

    # Check all characters are in char_space
    if all(c in char_space for c in link_name):
        return True

    return False
