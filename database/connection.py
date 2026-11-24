import sqlite3
from pathlib import Path

# Find database folder
DATABASE_DIR = Path(__file__).resolve().parent

# Database file will be created inside database
DATABASE_PATH = DATABASE_DIR / "edr.db"

# SQL file containing our CREATE TABLE statements
SCHEMA_PATH = DATABASE_DIR / "schema.sql"


def get_connection(database_path=DATABASE_PATH):
    """Open a SQLite connection with foreign keys enabled."""

    # Connect to the database file
    connection = sqlite3.connect(database_path)

    # We can access individual row by name, like row["endpoint"] -> FOR repository.py
    connection.row_factory = sqlite3.Row

    # Enforce relationships between tables, basically SQLite rejects inserting in SQL, makes sure both keys reference each other
    connection.execute("PRAGMA foreign_kets = ON")

    return connection


def initialise_database(database_path=DATABASE_PATH):
    """Create the database tables uising schema.sql"""

    # Read the SQL schema from our file
    schema = SCHEMA_PATH.read_text(encoding="utf-8")

    # Open a database connection
    connection = get_connection(database_path)

    try:
        # Execute all CREATE TABLE statements
        connection.executescript(schema)

        # Save changes
        connection.commit()

    except Exception:
        # Undo pending changes if possible
        connection.rollback()
        raise

    finally:
        # Close connection
        connection.close()
