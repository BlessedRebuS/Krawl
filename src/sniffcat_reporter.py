import requests

from config import get_config
from logger import get_app_logger

CATEGORIES = {
    "attacker": [15, 21],
    "bad_crawler": [15, 21],
}


def _build_comment(category: str, access_log: dict | None) -> str:
    if access_log:
        method = access_log.get("method", "GET")
        path = access_log.get("path", "/")
        ua = access_log.get("user_agent", "unknown")
    else:
        method = "GET"
        path = "/"
        ua = "unknown"

    return (
        f"Krawl honeypot report:\n"
        f"Krawl Category: {category}\n"
        f"Protocol: HTTP/1.1 ({method} method)\n"
        f"Endpoint: {path}\n"
        f"UA: {ua}"
    )


def report_ip(ip: str, category: str, access_log: dict | None = None) -> bool:
    config = get_config()
    app_logger = get_app_logger()

    if not config.sniffcat_enabled or not config.sniffcat_api_key:
        app_logger.debug("SniffCat reporting is disabled or missing API key")
        return False

    sniffcat_categories = CATEGORIES.get(category)
    if not sniffcat_categories:
        app_logger.debug(f"No SniffCat category mapping for Krawl category '{category}'")
        return False

    comment = _build_comment(category, access_log)

    payload = {
        "ip": ip,
        "categories": sniffcat_categories,
        "comment": comment,
    }

    headers = {
        "X-Secret-Token": config.sniffcat_api_key,
        "Content-Type": "application/json",
    }

    url = config.sniffcat_api_url.rstrip("/") + "/report"

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            app_logger.info(
                f"Reported {ip} ({category}) to SniffCat — "
                f"abuse confidence: {data.get('abuseConfidenceScore', '?')} "
                f"(delta: {data.get('delta', '?')})"
            )
            return True
        else:
            app_logger.warning(
                f"SniffCat report failed for {ip}: HTTP {response.status_code} — {response.text[:200]}"
            )
            return False
    except requests.RequestException as e:
        app_logger.warning(f"SniffCat report request failed for {ip}: {e}")
        return False
