# tasks/db_dump.py

import os
import shutil
import sqlite3
import subprocess
from logger import get_app_logger
from config import get_config

config = get_config()
app_logger = get_app_logger()

# ----------------------
# TASK CONFIG
# ----------------------
TASK_CONFIG = {
    "name": "dump-krawl-data",
    "cron": f"{config.backups_cron}",
    "enabled": config.backups_enabled,
    "run_when_loaded": True,
}


# ----------------------
# TASK LOGIC
# ----------------------
def _dump_sqlite():
    """Use SQLite's built-in backup API to create a database copy."""
    task_name = TASK_CONFIG.get("name")
    db_path = config.database_path

    os.makedirs(config.backups_path, exist_ok=True)
    output_file = os.path.join(config.backups_path, "krawl_backup.db")
    tmp_file = output_file + ".tmp"

    try:
        source = sqlite3.connect(db_path)
        dest = sqlite3.connect(tmp_file)
        source.backup(dest)
        dest.close()
        source.close()

        # Atomic rename so a partial backup never replaces a good one
        shutil.move(tmp_file, output_file)

        size = os.path.getsize(output_file)
        app_logger.info(
            f"[Background Task] {task_name} SQLite backup completed: "
            f"{output_file} ({size} bytes)"
        )
    except Exception as e:
        app_logger.error(f"[Background Task] {task_name} SQLite backup failed: {e}")
        if os.path.exists(tmp_file):
            os.remove(tmp_file)


def _dump_pg():
    """Use pg_dump for PostgreSQL backups (scalable mode)."""
    task_name = TASK_CONFIG.get("name")

    host = config.postgres_host
    port = str(config.postgres_port)
    user = config.postgres_user
    password = config.postgres_password
    database = config.postgres_database

    os.makedirs(config.backups_path, exist_ok=True)
    output_file = os.path.join(config.backups_path, "db_dump.sql")

    env = os.environ.copy()
    env["PGPASSWORD"] = password

    cmd = [
        "pg_dump",
        "-h", host,
        "-p", port,
        "-U", user,
        "-d", database,
        "--no-owner",
        "--no-privileges",
        "-f", output_file,
    ]

    try:
        result = subprocess.run(
            cmd, env=env, capture_output=True, text=True, timeout=300
        )
        if result.returncode == 0:
            size = os.path.getsize(output_file)
            app_logger.info(
                f"[Background Task] {task_name} PostgreSQL dump completed: "
                f"{output_file} ({size} bytes)"
            )
        else:
            app_logger.error(
                f"[Background Task] {task_name} pg_dump failed "
                f"(exit {result.returncode}): {result.stderr.strip()}"
            )
    except FileNotFoundError:
        app_logger.error(
            f"[Background Task] {task_name} pg_dump not found. "
            "Install postgresql-client to enable PostgreSQL backups."
        )
    except subprocess.TimeoutExpired:
        app_logger.error(
            f"[Background Task] {task_name} pg_dump timed out after 300s"
        )


def main():
    """Backup the database using native tools for each mode."""
    if config.mode == "scalable":
        _dump_pg()
    else:
        _dump_sqlite()
