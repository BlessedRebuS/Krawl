"""Database package for the Krawl honeypot.

Re-exports the public API so existing `from database import ...` callers
keep working unchanged. Domain query methods live in sub-repositories
exposed as attributes on DatabaseManager (db.access_logs, db.ip_stats, ...).
"""

from database.core import (
    DatabaseManager,
    get_database,
    get_write_buffer_size,
    initialize_database,
)

__all__ = [
    "DatabaseManager",
    "get_database",
    "get_write_buffer_size",
    "initialize_database",
]
