#!/usr/bin/env python3

"""Build the PostgreSQL covering indexes off the startup path."""

from database import get_database
from migrations.runner import build_online_indexes

TASK_CONFIG = {
    "name": "build-online-indexes",
    "cron": "17 * * * *",
    "enabled": True,
    "run_when_loaded": True,
    "single_pod": True,
}


def main():
    build_online_indexes(get_database().engine)
