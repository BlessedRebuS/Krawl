"""
Migration runner for Krawl.
Checks the database schema and applies any pending migrations at startup.
All checks are idempotent — safe to run on every boot.

Uses SQLAlchemy Inspector for dialect-agnostic schema introspection,
supporting both SQLite (standalone mode) and PostgreSQL (scalable mode).

Note: table creation (e.g. category_history) is already handled by
Base.metadata.create_all() in DatabaseManager.initialize() and is NOT
duplicated here. This runner only covers ALTER-level changes that
create_all() cannot apply to existing tables (new columns, new indexes).
"""

import logging

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

logger = logging.getLogger("krawl")


def _column_exists(engine: Engine, table_name: str, column_name: str) -> bool:
    """Check if a column exists in a table using SQLAlchemy Inspector."""
    insp = inspect(engine)
    columns = [c["name"] for c in insp.get_columns(table_name)]
    return column_name in columns


def _index_exists(engine: Engine, table_name: str, index_name: str) -> bool:
    """Check if an index exists on a table using SQLAlchemy Inspector."""
    insp = inspect(engine)
    indexes = [idx["name"] for idx in insp.get_indexes(table_name)]
    return index_name in indexes


def _migrate_raw_request_column(engine: Engine) -> bool:
    """Add raw_request column to access_logs if missing."""
    if _column_exists(engine, "access_logs", "raw_request"):
        return False
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE access_logs ADD COLUMN raw_request TEXT"))
    return True


def _migrate_need_reevaluation_column(engine: Engine) -> bool:
    """Add need_reevaluation column to ip_stats if missing."""
    if _column_exists(engine, "ip_stats", "need_reevaluation"):
        return False
    with engine.begin() as conn:
        conn.execute(
            text(
                "ALTER TABLE ip_stats ADD COLUMN need_reevaluation BOOLEAN DEFAULT false"
            )
        )
    return True


def _migrate_has_triggered_honeypot_column(engine: Engine) -> bool:
    """Add has_triggered_honeypot column to ip_stats if missing."""
    if _column_exists(engine, "ip_stats", "has_triggered_honeypot"):
        return False
    with engine.begin() as conn:
        conn.execute(
            text(
                "ALTER TABLE ip_stats ADD COLUMN has_triggered_honeypot "
                "BOOLEAN DEFAULT false"
            )
        )
    return True


def _migrate_ban_state_columns(engine: Engine) -> list[str]:
    """Add ban/rate-limit columns to ip_stats if missing."""
    added = []
    columns = {
        "page_visit_count": "INTEGER DEFAULT 0",
        "ban_timestamp": "DATETIME",
        "total_violations": "INTEGER DEFAULT 0",
        "ban_multiplier": "INTEGER DEFAULT 1",
    }
    for col_name, col_type in columns.items():
        if not _column_exists(engine, "ip_stats", col_name):
            with engine.begin() as conn:
                conn.execute(
                    text(f"ALTER TABLE ip_stats ADD COLUMN {col_name} {col_type}")
                )
            added.append(col_name)
    return added


def _migrate_performance_indexes(engine: Engine) -> list[str]:
    """Add performance indexes to attack_detections if missing."""
    added = []
    if not _index_exists(
        engine, "attack_detections", "ix_attack_detections_attack_type"
    ):
        with engine.begin() as conn:
            conn.execute(
                text(
                    "CREATE INDEX ix_attack_detections_attack_type "
                    "ON attack_detections(attack_type)"
                )
            )
        added.append("ix_attack_detections_attack_type")

    if not _index_exists(engine, "attack_detections", "ix_attack_detections_type_log"):
        with engine.begin() as conn:
            conn.execute(
                text(
                    "CREATE INDEX ix_attack_detections_type_log "
                    "ON attack_detections(attack_type, access_log_id)"
                )
            )
        added.append("ix_attack_detections_type_log")

    return added


def _migrate_scalable_indexes(engine: Engine) -> list[str]:
    """Add indexes for query performance (benefits both SQLite and PostgreSQL)."""
    added = []

    # (index_name, table, column)
    indexes = [
        ("ix_access_logs_path", "access_logs", "path"),
        ("ix_access_logs_user_agent", "access_logs", "user_agent"),
        ("ix_access_logs_is_suspicious", "access_logs", "is_suspicious"),
        ("ix_access_logs_is_honeypot_trigger", "access_logs", "is_honeypot_trigger"),
        ("ix_ip_stats_category", "ip_stats", "category"),
        ("ix_ip_stats_need_reevaluation", "ip_stats", "need_reevaluation"),
        ("ix_ip_stats_total_requests", "ip_stats", "total_requests"),
    ]
    for idx_name, table, column in indexes:
        if not _index_exists(engine, table, idx_name):
            try:
                with engine.begin() as conn:
                    conn.execute(text(f"CREATE INDEX {idx_name} ON {table}({column})"))
                added.append(idx_name)
            except Exception as e:
                logger.error(f"Failed to create index {idx_name}: {e}")
    return added


def _migrate_ban_override_column(engine: Engine) -> bool:
    """Add ban_override column to ip_stats if missing."""
    if _column_exists(engine, "ip_stats", "ban_override"):
        return False
    with engine.begin() as conn:
        conn.execute(
            text("ALTER TABLE ip_stats ADD COLUMN ban_override BOOLEAN DEFAULT NULL")
        )
    return True


def run_migrations(engine: Engine) -> None:
    """
    Check the database schema and apply any pending migrations.

    Only handles ALTER-level changes (columns, indexes) that
    Base.metadata.create_all() cannot apply to existing tables.

    Args:
        engine: SQLAlchemy Engine instance (works with any dialect).
    """
    applied: list[str] = []

    # Each migration runs in its own try/except so that one failure does not
    # abort the rest of the chain (a single bad ALTER must not leave later
    # columns/indexes unapplied).
    def _step(label: str, fn):
        try:
            result = fn()
            if isinstance(result, list):
                for item in result:
                    applied.append(f"add {item}")
            elif result:
                applied.append(label)
        except Exception as e:
            logger.error(f"Migration error ({label}): {e}")

    _step(
        "add raw_request column to access_logs",
        lambda: _migrate_raw_request_column(engine),
    )
    _step(
        "add need_reevaluation column to ip_stats",
        lambda: _migrate_need_reevaluation_column(engine),
    )
    _step(
        "add has_triggered_honeypot column to ip_stats",
        lambda: _migrate_has_triggered_honeypot_column(engine),
    )
    _step(
        "ban state columns on ip_stats",
        lambda: [f"{c} column to ip_stats" for c in _migrate_ban_state_columns(engine)],
    )
    _step(
        "add ban_override column to ip_stats",
        lambda: _migrate_ban_override_column(engine),
    )
    _step(
        "performance indexes",
        lambda: [f"index {i}" for i in _migrate_performance_indexes(engine)],
    )
    _step(
        "scalable indexes",
        lambda: [f"index {i}" for i in _migrate_scalable_indexes(engine)],
    )

    if applied:
        for m in applied:
            logger.info(f"Migration applied: {m}")
        logger.info(f"All migrations complete ({len(applied)} applied)")
    else:
        logger.info("Database schema is up to date — no migrations needed")
