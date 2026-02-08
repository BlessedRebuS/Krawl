# Database Migrations

This directory contains database migration scripts for Krawl.
From the 1.0.0 stable version we added some features that require schema changes and performance optimizations. These migration scripts ensure that existing users can seamlessly upgrade without data loss or downtime.

## Available Migrations

### add_raw_request_column.py

Adds the `raw_request` column to the `access_logs` table to store complete HTTP requests for forensic analysis.

**Usage:**
```bash
# Run with default database path (src/data/krawl.db)
python3 migrations/add_raw_request_column.py

# Run with custom database path
python3 migrations/add_raw_request_column.py /path/to/krawl.db
```

### add_performance_indexes.py

Adds critical performance indexes to the `attack_detections` table for efficient aggregation and filtering with large datasets (100k+ records).

**Indexes Added:**
- `ix_attack_detections_attack_type` - Speeds up GROUP BY on attack_type
- `ix_attack_detections_type_log` - Composite index for attack_type + access_log_id

**Usage:**
```bash
# Run with default database path
python3 migrations/add_performance_indexes.py

# Run with custom database path
python3 migrations/add_performance_indexes.py /path/to/krawl.db
```

**Post-Migration Optimization:**
```bash
# Compact database and update query planner statistics
sqlite3 /path/to/krawl.db "VACUUM; ANALYZE;"
```

## Running Migrations

All migration scripts are designed to be idempotent and safe to run multiple times. They will:
1. Check if the migration is already applied
2. Skip if already applied
3. Apply the migration if needed
4. Report the result

## Creating New Migrations

When creating a new migration:
1. Name the file descriptively: `action_description.py`
2. Make it idempotent (safe to run multiple times)
3. Add checks before making changes
4. Provide clear error messages
5. Support custom database paths via command line
6. Update this README with usage instructions
