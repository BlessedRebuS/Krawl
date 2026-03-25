#!/usr/bin/env python3
"""
Migrate data from SQLite (standalone mode) to MariaDB (scalable mode).

Usage:
    python scripts/migrate_sqlite_to_mariadb.py \
        --sqlite-path data/krawl.db \
        --mariadb-host localhost \
        --mariadb-port 3306 \
        --mariadb-user krawl \
        --mariadb-password krawl \
        --mariadb-database krawl \
        [--batch-size 1000] \
        [--drop-existing]

This script:
1. Connects to the source SQLite database
2. Connects to the target MariaDB database
3. Creates the schema in MariaDB (via SQLAlchemy create_all)
4. Copies all rows table-by-table in batches
5. Reports row counts for verification

Run this BEFORE switching your deployment to scalable mode.
"""

import argparse
import sys
import os

# Add src/ to path so we can import models
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sqlalchemy import create_engine, text, inspect, event
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


def create_mariadb_engine(host, port, user, password, database):
    url = f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}?charset=utf8mb4"
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

    # Get column names from the model
    mapper = inspect(model_class)
    columns = [c.key for c in mapper.column_attrs]

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
                row_dict[col] = getattr(row, col)
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
        description="Migrate Krawl data from SQLite to MariaDB"
    )
    parser.add_argument(
        "--sqlite-path",
        required=True,
        help="Path to the SQLite database file",
    )
    parser.add_argument("--mariadb-host", default="localhost")
    parser.add_argument("--mariadb-port", type=int, default=3306)
    parser.add_argument("--mariadb-user", default="krawl")
    parser.add_argument("--mariadb-password", default="krawl")
    parser.add_argument("--mariadb-database", default="krawl")
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Number of rows per batch insert (default: 1000)",
    )
    parser.add_argument(
        "--drop-existing",
        action="store_true",
        help="Drop existing MariaDB tables before migration",
    )
    args = parser.parse_args()

    if not os.path.exists(args.sqlite_path):
        print(f"Error: SQLite database not found at {args.sqlite_path}")
        sys.exit(1)

    print("=== Krawl SQLite -> MariaDB Migration ===\n")

    # Connect to both databases
    print("Connecting to SQLite...")
    src_engine = create_sqlite_engine(args.sqlite_path)

    print(
        f"Connecting to MariaDB at {args.mariadb_host}:{args.mariadb_port}/{args.mariadb_database}..."
    )
    dst_engine = create_mariadb_engine(
        args.mariadb_host,
        args.mariadb_port,
        args.mariadb_user,
        args.mariadb_password,
        args.mariadb_database,
    )

    # Test MariaDB connection
    try:
        with dst_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        print("MariaDB connection OK\n")
    except Exception as e:
        print(f"Error: Cannot connect to MariaDB: {e}")
        sys.exit(1)

    # Optionally drop existing tables
    if args.drop_existing:
        print("Dropping existing MariaDB tables...")
        Base.metadata.drop_all(dst_engine)

    # Create schema in MariaDB
    print("Creating schema in MariaDB...")
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

    # Summary
    print("\n=== Migration Summary ===")
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
