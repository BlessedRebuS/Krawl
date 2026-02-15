# tasks/db_dump.py

from logger import get_app_logger
from database import get_database
from config import get_config
from sqlalchemy import MetaData
from sqlalchemy.schema import CreateTable
import os

config = get_config()
app_logger = get_app_logger()

# ----------------------
# TASK CONFIG
# ----------------------
TASK_CONFIG = {
    "name": "dump-krawl-data",
    "cron": f"{config.backups_cron}",
    "enabled": True,
    "run_when_loaded": True,
}


# ----------------------
# TASK LOGIC
# ----------------------
def main():
    """
    Dump krawl database to a sql file for backups
    """
    task_name = TASK_CONFIG.get("name")
    app_logger.info(f"[Background Task] {task_name} starting...")

    try:
        db = get_database()
        engine = db._engine

        metadata = MetaData()
        metadata.reflect(bind=engine)

        # create backup directory
        os.makedirs(config.backups_path, exist_ok=True)
        output_file = os.path.join(config.backups_path, "db_dump.sql")

        with open(output_file, "w") as f:
            # Write header
            app_logger.info(f"[Background Task] {task_name} started database dump")

            # Dump schema (CREATE TABLE statements)
            f.write("-- Schema\n")
            f.write("-- " + "=" * 70 + "\n\n")

            for table_name in metadata.tables:
                table = metadata.tables[table_name]
                app_logger.info(
                    f"[Background Task] {task_name} dumping {table} table schema"
                )

                # Create table statement
                create_stmt = str(CreateTable(table).compile(engine))
                f.write(f"{create_stmt};\n\n")

            f.write("\n-- Data\n")
            f.write("-- " + "=" * 70 + "\n\n")

            with engine.connect() as conn:
                for table_name in metadata.tables:
                    table = metadata.tables[table_name]

                    f.write(f"-- Table: {table_name}\n")

                    # Select all data from table
                    result = conn.execute(table.select())
                    rows = result.fetchall()

                    if rows:
                        app_logger.info(
                            f"[Background Task] {task_name} dumping {table} content"
                        )
                        for row in rows:
                            # Build INSERT statement
                            columns = ", ".join([col.name for col in table.columns])
                            values = ", ".join([repr(value) for value in row])
                            f.write(
                                f"INSERT INTO {table_name} ({columns}) VALUES ({values});\n"
                            )

                        f.write("\n")
                    else:
                        f.write(f"-- No data in {table_name}\n\n")
                        app_logger.info(
                            f"[Background Task] {task_name} no data in {table}"
                        )

        app_logger.info(
            f"[Background Task] {task_name} Database dump completed: {output_file}"
        )

    except Exception as e:
        app_logger.error(f"[Background Task] {task_name} failed: {e}")
    finally:
        db.close_session()
