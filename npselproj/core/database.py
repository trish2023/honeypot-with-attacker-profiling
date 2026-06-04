"""SQLite database layer (PRD Section 5.8).

A single shared connection is used across all handler threads
(`check_same_thread=False`) and guarded by a module-level lock. WAL mode is
enabled so the dashboard can read concurrently with writes.
"""

import sqlite3
import threading
import time

from core.enrichment import lookup_geo

DB_PATH = "honeytrap.db"

_db_lock = threading.Lock()
_db_conn = None


def get_db() -> sqlite3.Connection:
    global _db_conn
    if _db_conn is None:
        _db_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _db_conn.execute("PRAGMA journal_mode=WAL")  # allows concurrent reads
        init_schema(_db_conn)
    return _db_conn


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            ip TEXT, port INTEGER, protocol TEXT,
            country TEXT, city TEXT,
            start_time REAL, classification TEXT,
            lat REAL, lon REAL
        );
        CREATE TABLE IF NOT EXISTS attempts (
            attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT, username TEXT, password TEXT,
            timestamp REAL, delay_ms REAL,
            is_default INTEGER, is_common INTEGER
        );
        CREATE TABLE IF NOT EXISTS shell_commands (
            command_id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT, command TEXT,
            timestamp REAL, intent_tag TEXT
        );
        """
    )
    _migrate(conn)
    conn.commit()


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns introduced after the initial schema to pre-existing DBs.
    Each ALTER is wrapped because SQLite raises if the column already exists."""
    for column, decl in (("lat", "REAL"), ("lon", "REAL")):
        try:
            conn.execute(f"ALTER TABLE sessions ADD COLUMN {column} {decl}")
        except sqlite3.OperationalError:
            pass


def db_insert_session(session_id, ip, port, protocol, geo=None, classification="unknown"):
    """Insert a new session row.

    ``geo`` may be a ``(country, city, lat, lon)`` tuple to bypass the live
    GeoIP lookup — used by the demo generator to plant attacks at chosen
    coordinates. When omitted, the source IP is resolved via GeoIP.
    """
    if geo is not None:
        country, city, lat, lon = geo
    else:
        country, city, lat, lon = lookup_geo(ip)
    with _db_lock:
        db = get_db()
        db.execute(
            "INSERT INTO sessions (session_id, ip, port, protocol, country, city, start_time, classification, lat, lon) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (session_id, ip, port, protocol, country, city, time.time(), classification, lat, lon),
        )
        db.commit()


def db_insert_attempt(session_id, username, password, timestamp, delay_ms, is_default, is_common):
    with _db_lock:
        db = get_db()
        db.execute(
            "INSERT INTO attempts (session_id, username, password, timestamp, delay_ms, is_default, is_common) "
            "VALUES (?,?,?,?,?,?,?)",
            (session_id, username, password, timestamp, delay_ms, is_default, is_common),
        )
        db.commit()


def db_update_classification(session_id, classification):
    with _db_lock:
        db = get_db()
        db.execute(
            "UPDATE sessions SET classification=? WHERE session_id=?",
            (classification, session_id),
        )
        db.commit()


def db_insert_shell_command(session_id, command, timestamp, intent_tag):
    with _db_lock:
        db = get_db()
        db.execute(
            "INSERT INTO shell_commands (session_id, command, timestamp, intent_tag) VALUES (?,?,?,?)",
            (session_id, command, timestamp, intent_tag),
        )
        db.commit()


def db_clear_all():
    """Wipe all captured data. Used by the dashboard to reset between demos."""
    with _db_lock:
        db = get_db()
        db.executescript(
            "DELETE FROM shell_commands; DELETE FROM attempts; DELETE FROM sessions;"
        )
        db.commit()
