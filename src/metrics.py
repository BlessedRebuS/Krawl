"""
Central Prometheus metric definitions and refresh helpers for Krawl.

Metrics are exposed at /{dashboard_secret}/metrics by the ASGI app mounted
in src/app.py. Refresh helpers are called from existing background tasks
(analyze_ips, dashboard_warmup) so we don't add any new cron entries.
"""

import re
import time

from prometheus_client import Gauge, REGISTRY

from config import get_config
from logger import get_app_logger

app_logger = get_app_logger()

CATEGORIES = ("attacker", "good_crawler", "bad_crawler", "regular_user")


# ----------------------
# Metric definitions
# ----------------------

# requests
accesses = Gauge(
    "accesses",
    "Total HTTP accesses recorded by Krawl",
    namespace="krawl",
    registry=REGISTRY,
)
unique_ips = Gauge(
    "unique_ips",
    "Number of distinct client IPs observed",
    namespace="krawl",
    registry=REGISTRY,
)
unique_paths = Gauge(
    "unique_paths",
    "Number of distinct request paths observed",
    namespace="krawl",
    registry=REGISTRY,
)

# detection
clients_total = Gauge(
    "clients_total",
    "Number of IPs per classification category",
    labelnames=["category"],
    namespace="krawl",
    registry=REGISTRY,
)
honeypot_triggers = Gauge(
    "honeypot_triggers",
    "Total honeypot trigger events",
    namespace="krawl",
    registry=REGISTRY,
)
honeypot_ips = Gauge(
    "honeypot_ips",
    "Distinct IPs that have triggered a honeypot path at least once",
    namespace="krawl",
    registry=REGISTRY,
)
credentials_captured = Gauge(
    "credentials_captured",
    "Total captured credential login attempts",
    namespace="krawl",
    registry=REGISTRY,
)
attack_detections = Gauge(
    "attack_detections",
    "Attack detections grouped by attack type",
    labelnames=["attack_type"],
    namespace="krawl",
    registry=REGISTRY,
)

# ai
generated_pages_today = Gauge(
    "generated_pages_today",
    "Deception pages generated today",
    namespace="krawl",
    registry=REGISTRY,
)

# system
ips_needing_reevaluation = Gauge(
    "ips_needing_reevaluation",
    "IPs currently flagged for reevaluation by the analyzer",
    namespace="krawl",
    registry=REGISTRY,
)
unenriched_ips = Gauge(
    "unenriched_ips",
    "IPs awaiting geolocation/reputation enrichment (capped at 1000)",
    namespace="krawl",
    registry=REGISTRY,
)
auth_locked_ips = Gauge(
    "auth_locked_ips",
    "Number of IPs currently locked out from dashboard authentication",
    namespace="krawl",
    registry=REGISTRY,
)
dashboard_warmup_duration_seconds = Gauge(
    "dashboard_warmup_duration_seconds",
    "Last observed duration of each dashboard_warmup sub-step",
    labelnames=["step"],
    namespace="krawl",
    registry=REGISTRY,
)


def _enabled() -> bool:
    return bool(get_config().metrics_enabled)


# ----------------------
# Refresh helpers
# ----------------------

def refresh_from_counters() -> None:
    """Populate counter-backed gauges from the live cache counters.

    Called at scrape time so every pod reports the shared values (each pod has
    its own in-process Prometheus registry).
    """
    if not _enabled():
        return
    import metrics_counters as c

    accesses.set(c.get("total_accesses"))
    unique_ips.set(c.get("unique_ips"))
    unique_paths.set(c.get("unique_paths"))
    honeypot_triggers.set(c.get("honeypot_triggered"))
    honeypot_ips.set(c.get("honeypot_ips"))
    credentials_captured.set(c.get("credentials_captured"))

    for category in CATEGORIES:
        clients_total.labels(category).set(c.get("clients_total", category))

    attack_detections.clear()
    for key, value in c.get_all().items():
        if key.startswith("attack_detections|"):
            attack_type = key.split("|", 1)[1]
            attack_detections.labels(attack_type).set(value)


def refresh_ai(db) -> None:
    if not _enabled():
        return
    generated_pages_today.set(db.count_generated_pages_created_today())


def refresh_system(db) -> None:
    if not _enabled():
        return
    try:
        ips_needing_reevaluation.set(len(db.get_ips_needing_reevaluation()))
    except Exception as e:
        app_logger.error(f"refresh_system: ips_needing_reevaluation failed: {e}")
    try:
        unenriched_ips.set(len(db.get_unenriched_ips(limit=1000)))
    except Exception as e:
        app_logger.error(f"refresh_system: unenriched_ips failed: {e}")

    try:
        from routes.api import _auth_attempts
        now = time.time()
        locked = sum(
            1
            for record in _auth_attempts.values()
            if record.get("locked_until", 0) > now
        )
        auth_locked_ips.set(locked)
    except Exception as e:
        app_logger.error(f"refresh_system: auth_locked_ips failed: {e}")


_WARMUP_PAGE_SUFFIX = re.compile(r"_p\d+$")


def observe_warmup_step(step: str, duration: float) -> None:
    if not _enabled():
        return
    collapsed = _WARMUP_PAGE_SUFFIX.sub("", step)
    dashboard_warmup_duration_seconds.labels(collapsed).set(duration)
