import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DB_PATH = Path(__file__).with_name("honeypot.db")

ATTEMPT_COLUMNS = (
    "timestamp",
    "ip",
    "port",
    "protocol",
    "username",
    "password",
    "country",
    "city",
    "lat",
    "lon",
    "credential_type",
    "behavior_class",
    "tool_fingerprint",
    "response_delay",
    "session_type",
)


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create the attempts table if it does not already exist."""
    with _get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                ip TEXT,
                port INTEGER,
                protocol TEXT CHECK(protocol IN ('SSH', 'FTP')),
                username TEXT,
                password TEXT,
                country TEXT,
                city TEXT,
                lat REAL,
                lon REAL,
                credential_type TEXT CHECK(credential_type IN ('default', 'common', 'unknown')),
                behavior_class TEXT CHECK(behavior_class IN ('bot', 'human', 'unknown')),
                tool_fingerprint TEXT,
                response_delay REAL,
                session_type TEXT CHECK(session_type IN ('rejected', 'accepted'))
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS shell_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                ip TEXT,
                commands TEXT
            )
            """
        )


def insert_attempt(attempt: dict[str, Any]) -> int:
    """Insert an attempt row and return the new row id."""
    values = [attempt.get(column) for column in ATTEMPT_COLUMNS]
    placeholders = ", ".join("?" for _ in ATTEMPT_COLUMNS)
    columns = ", ".join(ATTEMPT_COLUMNS)

    with _get_connection() as conn:
        cursor = conn.execute(
            f"INSERT INTO attempts ({columns}) VALUES ({placeholders})",
            values,
        )
        return int(cursor.lastrowid)


def get_all_attempts() -> list[dict[str, Any]]:
    """Return every stored attempt as a list of dictionaries."""
    with _get_connection() as conn:
        rows = conn.execute("SELECT * FROM attempts ORDER BY id").fetchall()
        return [dict(row) for row in rows]


def log_shell_session(ip: str, commands: list[dict[str, str]]) -> int:
    """Persist a captured fake shell session and return the new row id."""
    init_db()
    timestamp = datetime.now(timezone.utc).isoformat()

    with _get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO shell_sessions (timestamp, ip, commands)
            VALUES (?, ?, ?)
            """,
            (timestamp, ip, json.dumps(commands)),
        )
        return int(cursor.lastrowid)
