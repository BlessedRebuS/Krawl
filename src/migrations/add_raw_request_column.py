#!/usr/bin/env python3

"""
Migration script to add raw_request column to access_logs table.
This script is safe to run multiple times - it checks if the column exists before adding it.
"""

import sqlite3
import sys
import os
from pathlib import Path


def column_exists(cursor, table_name: str, column_name: str) -> bool:
    """Check if a column exists in a table."""
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [row[1] for row in cursor.fetchall()]
    return column_name in columns


def add_raw_request_column(db_path: str) -> bool:
    """
    Add raw_request column to access_logs table if it doesn't exist.

    Args:
        db_path: Path to the SQLite database file

    Returns:
        True if column was added or already exists, False on error
    """
    try:
        # Check if database exists
        if not os.path.exists(db_path):
            print(f"Database file not found: {db_path}")
            return False

        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if column already exists
        if column_exists(cursor, "access_logs", "raw_request"):
            print("Column 'raw_request' already exists in access_logs table")
            conn.close()
            return True

        # Add the column
        print("Adding 'raw_request' column to access_logs table...")
        cursor.execute("""
            ALTER TABLE access_logs 
            ADD COLUMN raw_request TEXT
        """)

        conn.commit()
        conn.close()

        print("✅ Successfully added 'raw_request' column to access_logs table")
        return True

    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False


def main():
    """Main migration function."""
    # Default database path
    default_db_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "data", "krawl.db"
    )

    # Allow custom path as command line argument
    db_path = sys.argv[1] if len(sys.argv) > 1 else default_db_path

    print(f"🔄 Running migration on database: {db_path}")
    print("=" * 60)

    success = add_raw_request_column(db_path)

    print("=" * 60)
    if success:
        print("Migration completed successfully")
        sys.exit(0)
    else:
        print("Migration failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
