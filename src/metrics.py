"""
Central Prometheus metric definitions for Krawl.

Metrics are exposed at /{dashboard_secret}/metrics by the ASGI app mounted
in src/app.py.

Two families of metrics:

- Cumulative totals (accesses, unique IPs/paths, honeypot, credentials, attack
  detections) are "total ever observed" values maintained in the cache counter
  store (see metrics_counters). They are exposed as proper Prometheus *counters*
  via KrawlMetricsCollector, which reads the values in batch at scrape time so
  every pod reports the shared totals and rate()/increase() work as expected.

- Current-state gauges (clients_total, reevaluation/enrichment/lock counts,
  warmup durations) are point-in-time values. clients_total is recomputed live
  in the collector; the rest are set by background tasks (analyze_ips,
  dashboard_warmup).
"""

import re
import time

from prometheus_client import REGISTRY, Gauge
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily

from config import get_config
from logger import get_app_logger

app_logger = get_app_logger()

CATEGORIES = ("attacker", "good_crawler", "bad_crawler", "regular_user")


def _enabled() -> bool:
    return bool(get_config().metrics_enabled)


# ----------------------
# Cumulative counters (cache-backed, exposed via custom collector)
# ----------------------

# (cache counter key, exposed metric name, help text). The exposed series get a
# "_total" suffix per Prometheus counter convention (e.g. krawl_accesses_total).
_CUMULATIVE = (
    ("total_accesses", "krawl_accesses", "Total HTTP accesses recorded by Krawl"),
    ("unique_ips", "krawl_unique_ips", "Number of distinct client IPs observed"),
    ("unique_paths", "krawl_unique_paths", "Number of distinct request paths observed"),
    ("honeypot_triggered", "krawl_honeypot_triggers", "Total honeypot trigger events"),
    (
        "honeypot_ips",
        "krawl_honeypot_ips",
        "Distinct IPs that have triggered a honeypot path at least once",
    ),
    (
        "credentials_captured",
        "krawl_credentials_captured",
        "Total captured credential login attempts",
    ),
)


class KrawlMetricsCollector:
    """Collector for cache-backed counters + current-state clients_total.

    Invoked by prometheus_client during scrape (generate_latest). Reads the
    cumulative counters from the cache in a single batched call, exposes them as
    counters, and recomputes clients_total live from the indexed category counts.
    """

    def collect(self):
        if not _enabled():
            return

        import metrics_counters as c

        values = c.get_many([key for key, _, _ in _CUMULATIVE])
        for key, name, doc in _CUMULATIVE:
            yield CounterMetricFamily(name, doc, value=values.get(key, 0))

        attacks = CounterMetricFamily(
            "krawl_attack_detections",
            "Attack detections grouped by attack type",
            labels=["attack_type"],
        )
        for ckey, value in c.get_all().items():
            if ckey.startswith("attack_detections|"):
                attacks.add_metric([ckey.split("|", 1)[1]], value)
        yield attacks

        # clients_total is current-state ("how many IPs are classified X right
        # now"), not cumulative — recompute live (4 indexed COUNTs). This avoids
        # the unbounded delta drift that previously produced negative values.
        clients = GaugeMetricFamily(
            "krawl_clients_total",
            "Number of IPs per classification category",
            labels=["category"],
        )
        try:
            from database import get_database

            db = get_database()
            for category in CATEGORIES:
                clients.add_metric([category], db.count_category(category))
        except Exception as e:
            app_logger.error(f"collect clients_total failed: {e}")
        yield clients


# Register the collector once (guard against re-import in test/reload paths).
_collector = KrawlMetricsCollector()
try:
    REGISTRY.register(_collector)
except ValueError:
    pass


# ----------------------
# Current-state gauges (set by background tasks)
# ----------------------

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


# ----------------------
# Refresh helpers (current-state gauges, called by background tasks)
# ----------------------

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
