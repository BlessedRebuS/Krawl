"""
Migration runner for Krawl.
Checks the database schema and applies any pending migrations at startup.
All checks are idempotent — safe to run on every boot.

Note: table creation (e.g. category_history) is already handled by
Base.metadata.create_all() in DatabaseManager.initialize() and is NOT
duplicated here. This runner only covers ALTER-level changes that
create_all() cannot apply to existing tables (new columns, new indexes).
"""

import sqlite3
import logging
from typing import List

logger = logging.getLogger("krawl")


def _column_exists(cursor, table_name: str, column_name: str) -> bool:
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [row[1] for row in cursor.fetchall()]
    return column_name in columns


def _index_exists(cursor, index_name: str) -> bool:
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name=?",
        (index_name,),
    )
    return cursor.fetchone() is not None


def _migrate_raw_request_column(cursor) -> bool:
    """Add raw_request column to access_logs if missing."""
    if _column_exists(cursor, "access_logs", "raw_request"):
        return False
    cursor.execute("ALTER TABLE access_logs ADD COLUMN raw_request TEXT")
    return True


def _migrate_need_reevaluation_column(cursor) -> bool:
    """Add need_reevaluation column to ip_stats if missing."""
    if _column_exists(cursor, "ip_stats", "need_reevaluation"):
        return False
    cursor.execute(
        "ALTER TABLE ip_stats ADD COLUMN need_reevaluation BOOLEAN DEFAULT 0"
    )
    return True


def _migrate_ban_state_columns(cursor) -> List[str]:
    """Add ban/rate-limit columns to ip_stats if missing."""
    added = []
    columns = {
        "page_visit_count": "INTEGER DEFAULT 0",
        "ban_timestamp": "DATETIME",
        "total_violations": "INTEGER DEFAULT 0",
        "ban_multiplier": "INTEGER DEFAULT 1",
    }
    for col_name, col_type in columns.items():
        if not _column_exists(cursor, "ip_stats", col_name):
            cursor.execute(f"ALTER TABLE ip_stats ADD COLUMN {col_name} {col_type}")
            added.append(col_name)
    return added


def _migrate_performance_indexes(cursor) -> List[str]:
    """Add performance indexes to attack_detections if missing."""
    added = []
    if not _index_exists(cursor, "ix_attack_detections_attack_type"):
        cursor.execute(
            "CREATE INDEX ix_attack_detections_attack_type "
            "ON attack_detections(attack_type)"
        )
        added.append("ix_attack_detections_attack_type")

    if not _index_exists(cursor, "ix_attack_detections_type_log"):
        cursor.execute(
            "CREATE INDEX ix_attack_detections_type_log "
            "ON attack_detections(attack_type, access_log_id)"
        )
        added.append("ix_attack_detections_type_log")

    return added


def run_migrations(database_path: str) -> None:
    """
    Check the database schema and apply any pending migrations.

    Only handles ALTER-level changes (columns, indexes) that
    Base.metadata.create_all() cannot apply to existing tables.

    Args:
        database_path: Path to the SQLite database file.
    """
    applied: List[str] = []

    try:
        conn = sqlite3.connect(database_path)
        cursor = conn.cursor()

        if _migrate_raw_request_column(cursor):
            applied.append("add raw_request column to access_logs")

        if _migrate_need_reevaluation_column(cursor):
            applied.append("add need_reevaluation column to ip_stats")

        ban_cols = _migrate_ban_state_columns(cursor)
        for col in ban_cols:
            applied.append(f"add {col} column to ip_stats")

        idx_added = _migrate_performance_indexes(cursor)
        for idx in idx_added:
            applied.append(f"add index {idx}")

        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        logger.error(f"Migration error: {e}")

    if applied:
        for m in applied:
            logger.info(f"Migration applied: {m}")
        logger.info(f"All migrations complete ({len(applied)} applied)")
    else:
        logger.info("Database schema is up to date — no migrations needed")
