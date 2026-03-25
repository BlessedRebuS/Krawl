#!/usr/bin/env python3
"""
Migrate data from SQLite (standalone mode) to PostgreSQL (scalable mode).

Usage:
    python scripts/migrate_sqlite_to_postgres.py \
        --sqlite-path data/krawl.db \
        --postgres-host localhost \
        --postgres-port 5432 \
        --postgres-user krawl \
        --postgres-password krawl \
        --postgres-database krawl \
        [--batch-size 1000] \
        [--drop-existing]

This script:
1. Connects to the source SQLite database
2. Connects to the target PostgreSQL database
3. Creates the schema in PostgreSQL (via SQLAlchemy create_all)
4. Copies all rows table-by-table in batches
5. Reports row counts for verification

Run this BEFORE switching your deployment to scalable mode.
"""

import argparse
import sys
import os

# Add src/ to path so we can import models
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sqlalchemy import create_engine, text, inspect, event, Integer, Float, Boolean
from sqlalchemy.orm import sessionmaker

from models import (
    Base,
    AccessLog,
    CredentialAttempt,
    AttackDetection,
    IpStats,
    CategoryHistory,
    TrackedIp,
)

# Order matters: tables with foreign keys must come after their parents
TABLES_IN_ORDER = [
    ("ip_stats", IpStats),
    ("access_logs", AccessLog),
    ("attack_detections", AttackDetection),
    ("credential_attempts", CredentialAttempt),
    ("category_history", CategoryHistory),
    ("tracked_ips", TrackedIp),
]


def create_sqlite_engine(path: str):
    engine = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()

    return engine


def create_postgres_engine(host, port, user, password, database):
    url = f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{database}"
    return create_engine(url, pool_size=5, pool_pre_ping=True)


def get_row_count(engine, table_name: str) -> int:
    with engine.connect() as conn:
        result = conn.execute(text(f"SELECT COUNT(*) FROM {table_name}"))
        return result.scalar()


def table_exists(engine, table_name: str) -> bool:
    insp = inspect(engine)
    return table_name in insp.get_table_names()


def migrate_table(
    src_engine, dst_engine, table_name: str, model_class, batch_size: int
) -> int:
    """Copy all rows from source to destination for a given table."""
    if not table_exists(src_engine, table_name):
        print(f"  Skipping {table_name} (does not exist in source)")
        return 0

    src_session = sessionmaker(bind=src_engine)()
    dst_session = sessionmaker(bind=dst_engine)()

    total = get_row_count(src_engine, table_name)
    if total == 0:
        print(f"  {table_name}: 0 rows (empty)")
        src_session.close()
        dst_session.close()
        return 0

    print(f"  {table_name}: {total} rows to migrate...")

    # Get column names and their types from the model for data sanitization
    mapper = inspect(model_class)
    columns = [c.key for c in mapper.column_attrs]

    # Build a map of column name -> SQLAlchemy type for sanitization
    col_types = {}
    for col in model_class.__table__.columns:
        col_types[col.name] = col.type

    migrated = 0
    offset = 0

    while offset < total:
        # Read batch from source
        rows = src_session.query(model_class).offset(offset).limit(batch_size).all()
        if not rows:
            break

        # Convert to dicts and bulk insert into destination
        batch_data = []
        for row in rows:
            row_dict = {}
            for col in columns:
                value = getattr(row, col)
                # Sanitize: SQLite allows empty strings in Integer/Float/Boolean columns,
                # PostgreSQL does not. Convert empty strings to None for non-string columns.
                if isinstance(value, str) and value == "" and col in col_types:
                    col_type = col_types[col]
                    if isinstance(col_type, (Integer, Float, Boolean)):
                        value = None
                row_dict[col] = value
            batch_data.append(row_dict)

        try:
            dst_session.bulk_insert_mappings(model_class, batch_data)
            dst_session.commit()
        except Exception as e:
            dst_session.rollback()
            print(f"    Error at offset {offset}: {e}")
            print(f"    Retrying row-by-row...")
            # Fall back to row-by-row for this batch
            for row_dict in batch_data:
                try:
                    dst_session.execute(
                        model_class.__table__.insert().values(**row_dict)
                    )
                    dst_session.commit()
                except Exception as row_err:
                    dst_session.rollback()
                    print(f"    Skipped row: {row_err}")

        migrated += len(rows)
        offset += batch_size

        if migrated % (batch_size * 10) == 0 or migrated == total:
            print(f"    {migrated}/{total} rows migrated")

    src_session.close()
    dst_session.close()
    return migrated


def main():
    parser = argparse.ArgumentParser(
        description="Migrate Krawl data from SQLite to PostgreSQL"
    )
    parser.add_argument(
        "--sqlite-path",
        required=True,
        help="Path to the SQLite database file",
    )
    parser.add_argument("--postgres-host", default="localhost")
    parser.add_argument("--postgres-port", type=int, default=5432)
    parser.add_argument("--postgres-user", default="krawl")
    parser.add_argument("--postgres-password", default="krawl")
    parser.add_argument("--postgres-database", default="krawl")
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Number of rows per batch insert (default: 1000)",
    )
    parser.add_argument(
        "--drop-existing",
        action="store_true",
        help="Drop existing PostgreSQL tables before migration",
    )
    args = parser.parse_args()

    if not os.path.exists(args.sqlite_path):
        print(f"Error: SQLite database not found at {args.sqlite_path}")
        sys.exit(1)

    print("=== Krawl SQLite -> PostgreSQL Migration ===\n")

    # Connect to both databases
    print("Connecting to SQLite...")
    src_engine = create_sqlite_engine(args.sqlite_path)

    print(
        f"Connecting to PostgreSQL at {args.postgres_host}:{args.postgres_port}/{args.postgres_database}..."
    )
    dst_engine = create_postgres_engine(
        args.postgres_host,
        args.postgres_port,
        args.postgres_user,
        args.postgres_password,
        args.postgres_database,
    )

    # Test PostgreSQL connection
    try:
        with dst_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        print("PostgreSQL connection OK\n")
    except Exception as e:
        print(f"Error: Cannot connect to PostgreSQL: {e}")
        sys.exit(1)

    # Optionally drop existing tables
    if args.drop_existing:
        print("Dropping existing PostgreSQL tables...")
        Base.metadata.drop_all(dst_engine)

    # Create schema in PostgreSQL
    print("Creating schema in PostgreSQL...")
    Base.metadata.create_all(dst_engine)
    print("Schema created\n")

    # Migrate each table
    print("Migrating data...\n")
    results = {}
    for table_name, model_class in TABLES_IN_ORDER:
        count = migrate_table(
            src_engine, dst_engine, table_name, model_class, args.batch_size
        )
        results[table_name] = count

    # Reset PostgreSQL sequences so auto-increment IDs don't collide
    # with migrated data that was inserted with explicit IDs from SQLite.
    # Only applies to integer primary keys with sequences (not text PKs like ip_stats.ip).
    print("\nResetting PostgreSQL sequences...")
    with dst_engine.begin() as conn:
        for table_name, model_class in TABLES_IN_ORDER:
            for col in model_class.__table__.columns:
                if col.primary_key and isinstance(col.type, Integer) and col.autoincrement:
                    seq_name = f"{table_name}_{col.name}_seq"
                    try:
                        conn.execute(
                            text(
                                f"SELECT setval('{seq_name}', "
                                f"COALESCE((SELECT MAX({col.name}) FROM {table_name}), 1))"
                            )
                        )
                        print(f"  Reset {seq_name}")
                    except Exception as e:
                        print(f"  Skipped {seq_name}: {e}")
    print("Sequences reset.\n")

    # Summary
    print("=== Migration Summary ===")
    for table_name, count in results.items():
        src_count = (
            get_row_count(src_engine, table_name)
            if table_exists(src_engine, table_name)
            else 0
        )
        dst_count = (
            get_row_count(dst_engine, table_name)
            if table_exists(dst_engine, table_name)
            else 0
        )
        status = "OK" if src_count == dst_count else "MISMATCH"
        print(f"  {table_name}: {src_count} -> {dst_count} [{status}]")

    print("\nMigration complete.")
    print(
        "You can now switch to scalable mode by setting KRAWL_MODE=scalable "
        "or mode: scalable in config.yaml."
    )


if __name__ == "__main__":
    main()
