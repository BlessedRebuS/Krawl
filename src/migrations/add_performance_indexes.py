#!/usr/bin/env python3

"""
Migration script to add performance indexes to attack_detections table.
This dramatically improves query performance with large datasets (100k+ records).
"""

import sqlite3
import sys
import os


def index_exists(cursor, index_name: str) -> bool:
    """Check if an index exists."""
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name=?", (index_name,)
    )
    return cursor.fetchone() is not None


def add_performance_indexes(db_path: str) -> bool:
    """
    Add performance indexes to optimize queries.

    Args:
        db_path: Path to the SQLite database file

    Returns:
        True if indexes were added or already exist, False on error
    """
    try:
        # Check if database exists
        if not os.path.exists(db_path):
            print(f"Database file not found: {db_path}")
            return False

        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        indexes_added = []
        indexes_existed = []

        # Index 1: attack_type for efficient GROUP BY operations
        if not index_exists(cursor, "ix_attack_detections_attack_type"):
            print("Adding index on attack_detections.attack_type...")
            cursor.execute("""
                CREATE INDEX ix_attack_detections_attack_type 
                ON attack_detections(attack_type)
            """)
            indexes_added.append("ix_attack_detections_attack_type")
        else:
            indexes_existed.append("ix_attack_detections_attack_type")

        # Index 2: Composite index for attack_type + access_log_id
        if not index_exists(cursor, "ix_attack_detections_type_log"):
            print(
                "Adding composite index on attack_detections(attack_type, access_log_id)..."
            )
            cursor.execute("""
                CREATE INDEX ix_attack_detections_type_log 
                ON attack_detections(attack_type, access_log_id)
            """)
            indexes_added.append("ix_attack_detections_type_log")
        else:
            indexes_existed.append("ix_attack_detections_type_log")

        conn.commit()
        conn.close()

        # Report results
        if indexes_added:
            print(f"Successfully added {len(indexes_added)} index(es):")
            for idx in indexes_added:
                print(f"   - {idx}")

        if indexes_existed:
            print(f"ℹ️  {len(indexes_existed)} index(es) already existed:")
            for idx in indexes_existed:
                print(f"   - {idx}")

        if not indexes_added and not indexes_existed:
            print("No indexes processed")

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

    print(f"Adding performance indexes to database: {db_path}")
    print("=" * 60)

    success = add_performance_indexes(db_path)

    print("=" * 60)
    if success:
        print("Migration completed successfully")
        print("\n💡 Performance tip: Run 'VACUUM' and 'ANALYZE' on your database")
        print("   to optimize query planner statistics after adding indexes.")
        sys.exit(0)
    else:
        print("Migration failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
