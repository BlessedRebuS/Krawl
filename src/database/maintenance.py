"""Planner-statistics maintenance for the Krawl database.

Autovacuum owns the steady state — see ``AUTOVACUUM`` in migrations/runner.py,
which lowers the per-table thresholds so it actually fires on tables this size.
This module covers the two moments autovacuum is structurally late for:

- **Boot on a database it has never analysed.** Autovacuum's trigger is a
  *count of modifications since the last analyze*, and PostgreSQL discards
  those counters on an unclean shutdown. A database that keeps restarting
  (an OOM-killed container, say) can therefore never accumulate enough to
  cross the threshold, and its tables stay unanalysed indefinitely — leaving
  the planner to size a multi-million-row table from its empty-table default.
  ``bootstrap_analyze`` breaks that cycle once, at boot.

- **Straight after the nightly retention purge.** A bulk delete invalidates the
  statistics at a moment the application knows about and autovacuum does not
  yet; analysing there costs one pass at 8 AM instead of a day of bad plans.

Both are PostgreSQL-only. SQLite has no autovacuum daemon and its own ANALYZE
is a different (and far cheaper) mechanism, so standalone mode skips them.
"""

import time

from sqlalchemy import text

from logger import get_app_logger

applogger = get_app_logger()

# Tables large enough for a wrong row estimate to change the plan. Kept in sync
# with AUTOVACUUM in migrations/runner.py.
ANALYZE_TABLES = ("ip_stats", "access_logs", "category_history", "attack_detections")


def _is_postgres(engine) -> bool:
    return engine.dialect.name == "postgresql"


def analyze_tables(engine, tables=ANALYZE_TABLES) -> int:
    """Run ANALYZE on `tables`. Returns the number successfully analysed.

    ANALYZE cannot run inside a transaction block, hence the AUTOCOMMIT
    isolation level rather than the usual ``engine.begin()``.

    Each table is analysed in its own statement so one failure (a table that
    does not exist yet on a fresh install) does not skip the rest.
    """
    if not _is_postgres(engine):
        return 0

    done = 0
    for table in tables:
        try:
            with engine.connect().execution_options(
                isolation_level="AUTOCOMMIT"
            ) as conn:
                conn.execute(text(f"ANALYZE {table}"))
            done += 1
        except Exception as e:
            applogger.error(f"ANALYZE {table} failed: {e}")
    return done


def bootstrap_analyze(engine) -> int:
    """Analyse any sizeable table that has never been analysed. Returns the count.

    A no-op on every boot after the first, because ``last_analyze`` /
    ``last_autoanalyze`` stay set once either has run. The size floor keeps a
    fresh install from paying for an ANALYZE of empty tables.

    That floor is deliberately measured with ``pg_relation_size`` rather than
    ``n_live_tup``: the row counters come from the same statistics this
    function exists to repair, and on a database that has never been analysed
    they read as near-zero however large the table actually is. Physical size
    is maintained independently of the statistics collector, so it stays
    truthful in exactly the situation we are detecting.
    """
    if not _is_postgres(engine):
        return 0

    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT relname FROM pg_stat_user_tables "
                    "WHERE relname = ANY(:tables) "
                    "  AND last_analyze IS NULL AND last_autoanalyze IS NULL "
                    "  AND pg_relation_size(relid) > 8 * 1024 * 1024"
                ),
                {"tables": list(ANALYZE_TABLES)},
            ).fetchall()
    except Exception as e:
        applogger.error(f"Bootstrap ANALYZE check failed: {e}")
        return 0

    pending = [r[0] for r in rows]
    if not pending:
        return 0

    applogger.info(
        f"Bootstrap ANALYZE: {', '.join(pending)} have never been analysed, "
        "collecting statistics…"
    )
    t0 = time.monotonic()
    done = analyze_tables(engine, pending)
    applogger.info(
        f"Bootstrap ANALYZE: analysed {done} table(s) in {time.monotonic() - t0:.1f}s"
    )
    return done
