"""
Migration runner for Krawl.
Applies pending ALTER-level schema changes at startup. All steps are idempotent
and dialect-agnostic (SQLite in standalone mode, PostgreSQL in scalable mode).

Note: table creation (e.g. category_history) is already handled by
Base.metadata.create_all() in DatabaseManager.initialize() and is NOT
duplicated here.
"""

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

from logger import get_app_logger

logger = get_app_logger()

# (table, column, SQL type) — added if the column is missing.
COLUMNS = [
    ("access_logs", "raw_request", "TEXT"),
    ("ip_stats", "need_reevaluation", "BOOLEAN DEFAULT false"),
    ("ip_stats", "has_triggered_honeypot", "BOOLEAN DEFAULT false"),
    ("ip_stats", "page_visit_count", "INTEGER DEFAULT 0"),
    ("ip_stats", "ban_timestamp", "DATETIME"),
    ("ip_stats", "total_violations", "INTEGER DEFAULT 0"),
    ("ip_stats", "ban_multiplier", "INTEGER DEFAULT 1"),
    ("ip_stats", "ban_override", "BOOLEAN DEFAULT NULL"),
    ("ip_stats", "timeout_exempt", "BOOLEAN DEFAULT false"),
    # Geolocation columns (previously applied by a separate sqlite3 migration).
    ("ip_stats", "latitude", "REAL"),
    ("ip_stats", "longitude", "REAL"),
    ("ip_stats", "country", "VARCHAR(100)"),
    ("ip_stats", "region", "VARCHAR(2)"),
    ("ip_stats", "region_name", "VARCHAR(100)"),
    ("ip_stats", "timezone", "VARCHAR(50)"),
    ("ip_stats", "isp", "VARCHAR(100)"),
    ("ip_stats", "is_proxy", "BOOLEAN"),
    ("ip_stats", "is_hosting", "BOOLEAN"),
    ("ip_stats", "reverse", "VARCHAR(255)"),
]

# (index name, table, column) — created if the index is missing.
INDEXES = [
    ("ix_attack_detections_attack_type", "attack_detections", "attack_type"),
    (
        "ix_attack_detections_type_log",
        "attack_detections",
        "attack_type, access_log_id",
    ),
    ("ix_access_logs_path", "access_logs", "path"),
    ("ix_access_logs_user_agent", "access_logs", "user_agent"),
    ("ix_access_logs_is_suspicious", "access_logs", "is_suspicious"),
    ("ix_access_logs_is_honeypot_trigger", "access_logs", "is_honeypot_trigger"),
    ("ix_ip_stats_category", "ip_stats", "category"),
    ("ix_ip_stats_need_reevaluation", "ip_stats", "need_reevaluation"),
    ("ix_ip_stats_total_requests", "ip_stats", "total_requests"),
    # Sort columns for paginated attacker / all-IP views.
    ("ix_ip_stats_last_seen", "ip_stats", "last_seen"),
    ("ix_ip_stats_first_seen", "ip_stats", "first_seen"),
    ("ix_ip_stats_reputation_score", "ip_stats", "reputation_score"),
    # Startup cleanup scans for live bans; the analyzer orders its queue by
    # last analysis time. Both were full scans of ip_stats without these.
    ("ix_ip_stats_ban_timestamp", "ip_stats", "ban_timestamp"),
    ("ix_ip_stats_last_analysis", "ip_stats", "last_analysis"),
]

# (table, {storage parameter: value}) — PostgreSQL only, applied with ALTER TABLE.
#
# The stock scale factors (0.2 vacuum / 0.1 analyze) are a fraction of the
# table, so they scale the *threshold* with the data: at 1.5M rows ip_stats
# waits for ~300k dead tuples before a vacuum and ~150k modifications before an
# analyze. On an append-mostly honeypot table that point arrives rarely or
# never, which leaves the planner sizing a multi-million-row table from its
# empty-table estimate and leaves dead index entries unreclaimed — a lookup
# that should return nothing then reads tens of MB to discover that.
#
# Lower factors plus a flat threshold keep both maintenance jobs firing on a
# schedule the table size cannot outrun.
AUTOVACUUM = [
    (
        table,
        {
            "autovacuum_vacuum_scale_factor": "0.02",
            "autovacuum_vacuum_threshold": "1000",
            "autovacuum_analyze_scale_factor": "0.01",
            "autovacuum_analyze_threshold": "1000",
        },
    )
    for table in ("ip_stats", "access_logs", "category_history", "attack_detections")
]


def _reloptions(engine: Engine, table: str) -> set[str]:
    """Current storage parameters of a table, as {"name=value"} (PostgreSQL).

    Returns an empty set when the table is missing or unreadable, so the caller
    simply applies the settings rather than failing.
    """
    try:
        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT unnest(coalesce(reloptions, '{}')) FROM pg_class "
                    "WHERE relname = :t AND relkind = 'r'"
                ),
                {"t": table},
            ).fetchall()
        return {r[0] for r in row}
    except Exception as e:
        logger.error(f"Migration error (reloptions {table}): {e}")
        return set()


def run_migrations(engine: Engine) -> None:
    """Apply any pending column/index migrations.

    Each step runs in its own transaction and its own try/except so one failure
    cannot leave the remaining steps unapplied.
    """
    insp = inspect(engine)
    applied: list[str] = []

    def _existing(kind: str, table: str) -> set | None:
        """Reflect current column/index names for a table (None if unreadable)."""
        try:
            rows = (
                insp.get_columns(table) if kind == "column" else insp.get_indexes(table)
            )
            return {r["name"] for r in rows}
        except Exception as e:
            logger.error(f"Migration error (inspect {table}): {e}")
            return None

    def _apply(label: str, sql: str) -> None:
        try:
            with engine.begin() as conn:
                conn.execute(text(sql))
            applied.append(label)
        except Exception as e:
            logger.error(f"Migration error ({label}): {e}")

    # Reflect everything up front: we only ever add, so a snapshot taken before
    # the first ALTER stays accurate (and avoids stale Inspector cache reads).
    columns = {t: _existing("column", t) for t in {t for t, _, _ in COLUMNS}}
    indexes = {t: _existing("index", t) for t in {t for _, t, _ in INDEXES}}

    for table, column, col_type in COLUMNS:
        if columns[table] is None or column in columns[table]:
            continue
        _apply(
            f"add {column} column to {table}",
            f"ALTER TABLE {table} ADD COLUMN {column} {col_type}",
        )

    for idx_name, table, column in INDEXES:
        if indexes[table] is None or idx_name in indexes[table]:
            continue
        _apply(f"add index {idx_name}", f"CREATE INDEX {idx_name} ON {table}({column})")

    # Storage parameters are a PostgreSQL concept; SQLite has no autovacuum
    # daemon to tune, so standalone mode skips this entirely.
    if engine.dialect.name == "postgresql":
        for table, params in AUTOVACUUM:
            # ALTER TABLE ... SET is harmless to repeat, but _apply() reports
            # every call as a migration, so compare against the table's current
            # reloptions first and stay silent when nothing changes.
            if _reloptions(engine, table) >= {f"{k}={v}" for k, v in params.items()}:
                continue
            settings = ", ".join(f"{k} = {v}" for k, v in params.items())
            _apply(
                f"tune autovacuum for {table}",
                f"ALTER TABLE {table} SET ({settings})",
            )

    if applied:
        for m in applied:
            logger.info(f"Migration applied: {m}")
        logger.info(f"All migrations complete ({len(applied)} applied)")
    else:
        logger.info("Database schema is up to date — no migrations needed")
