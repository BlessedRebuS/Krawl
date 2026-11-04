"""Extract bounded, dashboard-queryable metadata from stored HTTP requests."""

import re
from urllib.parse import urlsplit

MAX_ASSETS_PER_REQUEST = 32
CURRENT_METADATA_VERSION = 2

_HOST_RE = re.compile(r"^Host:\s*([^\r\n]+)", re.IGNORECASE | re.MULTILINE)
_FORWARDED_HOST_RE = re.compile(
    r"^X-Forwarded-Host:\s*([^\r\n,]+)", re.IGNORECASE | re.MULTILINE
)
_FORWARDED_RE = re.compile(r"^Forwarded:\s*([^\r\n]+)", re.IGNORECASE | re.MULTILINE)
_FORWARDED_HOST_PARAM_RE = re.compile(
    r"(?:^|[;,])\s*host=(?:\"([^\"]+)\"|([^;,\s]+))", re.IGNORECASE
)
_REFERER_RE = re.compile(r"^Referer:\s*([^\r\n]+)", re.IGNORECASE | re.MULTILINE)
_URL_RE = re.compile(r"https?://[^\s<>\"'\x00-\x1f]+", re.IGNORECASE)


def normalize_target_host(value: str) -> str | None:
    """Return a lowercase hostname, removing a port and trailing root dot."""
    value = (value or "").strip()
    if not value:
        return None
    try:
        hostname = urlsplit(f"//{value}").hostname
    except ValueError:
        return None
    return hostname.lower().rstrip(".")[:255] if hostname else None


def extract_request_metadata(raw_request: str) -> tuple[str | None, list[str]]:
    """Return ``(target_host, URL occurrences)`` from a raw HTTP request.

    URL occurrences intentionally retain duplicates: the dashboard count means
    how many times an asset appeared, rather than how many requests contained it.
    Work is capped because this runs on the request-ingestion path.
    """
    if not raw_request:
        return None, []

    headers = raw_request.partition("\r\n\r\n")[0]
    forwarded = _FORWARDED_RE.search(headers)
    forwarded_param = (
        _FORWARDED_HOST_PARAM_RE.search(forwarded.group(1)) if forwarded else None
    )
    forwarded_host = _FORWARDED_HOST_RE.search(headers)
    host = _HOST_RE.search(headers)
    # The HTTP Host field is the requested target and therefore authoritative.
    # Forwarded variants are fallbacks for proxy captures that omit Host.
    raw_host = (
        host.group(1)
        if host
        else (
            forwarded_host.group(1)
            if forwarded_host
            else (
                (forwarded_param.group(1) or forwarded_param.group(2))
                if forwarded_param
                else ""
            )
        )
    )
    target_host = normalize_target_host(raw_host)

    assets = []
    for match in _URL_RE.finditer(raw_request):
        # Strip punctuation that commonly terminates URLs in prose, JSON, XML,
        # or form values. URL-internal punctuation remains untouched.
        url = match.group(0).rstrip(".,;!?)]}\\")[:2048]
        if url:
            assets.append(url)
        if len(assets) >= MAX_ASSETS_PER_REQUEST:
            break
    return target_host, assets


def extract_request_referer(raw_request: str) -> str | None:
    """Extract a Referer header for historical rows that predate its column."""
    if not raw_request:
        return None
    match = _REFERER_RE.search(raw_request.partition("\r\n\r\n")[0])
    return match.group(1).strip()[:2048] if match else None
