import sqlite3
import sys

def get_db() -> sqlite3.Connection:
    db = sqlite3.connect("db.sqlite3")
    db.execute("PRAGMA foreign_keys = ON")
    db.row_factory = sqlite3.Row
    return db

def add_command_to_db(client_id, run_after, command_path):
    with get_db() as db, open(command_path, "rb") as f:
        db.execute(
            """
            INSERT INTO commands (client, run_after, content)
            VALUES (?,?,?)
            ON CONFLICT(client, run_after)
            DO UPDATE SET content=excluded.content, delivered=FALSE
            """,
            (client_id, run_after, f.read()),
        )

add_command_to_db(sys.argv[1], sys.argv[2], sys.argv[3])