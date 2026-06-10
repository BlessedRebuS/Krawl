# tasks/metrics_flush.py

"""
Persist the live heavy-aggregate counters into the metrics_summary table.

Runs on a slow schedule so the dashboard and Prometheus survive restarts
without recomputing full COUNT/COUNT(DISTINCT) scans. Steady-state drift is
bounded by the flush interval, corrected on the next startup reseed.
"""

import metrics_counters as mc
from database import get_database
from logger import get_app_logger

app_logger = get_app_logger()

TASK_CONFIG = {
    "name": "metrics-flush",
    "cron": "*/2 * * * *",
    "enabled": True,
    "run_when_loaded": False,
}


def main():
    task_name = TASK_CONFIG.get("name")
    try:
        db = get_database()
        values = {(metric, ""): mc.get(metric) for metric in mc.HEAVY_METRICS}
        db.upsert_metrics_summary(values)
        app_logger.info(f"[Background Task] {task_name} flushed {len(values)} counters.")
    except Exception as e:
        app_logger.error(f"[Background Task] {task_name} failed: {e}")
