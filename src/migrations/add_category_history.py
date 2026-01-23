#!/usr/bin/env python3
"""
Migration script to add CategoryHistory table to existing databases.
Run this once to upgrade your database schema.
"""

import sys
from pathlib import Path

# Add parent directory to path to import modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from database import get_database, DatabaseManager
from models import Base, CategoryHistory


def migrate():
    """Create CategoryHistory table if it doesn't exist."""
    print("Starting migration: Adding CategoryHistory table...")

    try:
        db = get_database()

        # Initialize database if not already done
        if not db._initialized:
            db.initialize()

        # Create only the CategoryHistory table
        CategoryHistory.__table__.create(db._engine, checkfirst=True)

        print("✓ Migration completed successfully!")
        print("  - CategoryHistory table created")

    except Exception as e:
        print(f"✗ Migration failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    migrate()
