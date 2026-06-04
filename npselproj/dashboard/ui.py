"""Rich terminal dashboard (PRD Section 5.10).

Reads live from SQLite and refreshes once per second, showing active sessions,
top credentials, geographic origins, and post-authentication intent.
"""

import time

from rich import box
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from core.database import get_db, _db_lock


def build_dashboard() -> Layout:
    # All reads share the single connection with the writer threads, so guard
    # them with the same lock to avoid concurrent-cursor errors.
    with _db_lock:
        db = get_db()

        # Active sessions in last 60s
        active = db.execute(
            "SELECT ip, protocol, classification, country FROM sessions WHERE start_time > ?",
            (time.time() - 60,),
        ).fetchall()

        # Top credentials
        top_creds = db.execute(
            "SELECT username, password, COUNT(*) as c FROM attempts "
            "GROUP BY username, password ORDER BY c DESC LIMIT 10"
        ).fetchall()

        # Geographic breakdown
        geo = db.execute(
            "SELECT country, COUNT(*) as c FROM sessions GROUP BY country ORDER BY c DESC LIMIT 5"
        ).fetchall()

        # Intent breakdown
        intents = db.execute(
            "SELECT intent_tag, COUNT(*) as c FROM shell_commands "
            "WHERE intent_tag IS NOT NULL GROUP BY intent_tag ORDER BY c DESC"
        ).fetchall()

    # Build tables
    session_table = Table(title="Active Sessions (last 60s)", box=box.SIMPLE, expand=True)
    session_table.add_column("IP")
    session_table.add_column("Protocol")
    session_table.add_column("Classification")
    session_table.add_column("Country")
    for row in active:
        color = "red" if row[2] == "bot" else "yellow"
        session_table.add_row(row[0], row[1], f"[{color}]{row[2]}[/{color}]", row[3] or "?")

    cred_table = Table(title="Top Credentials", box=box.SIMPLE, expand=True)
    cred_table.add_column("Username")
    cred_table.add_column("Password")
    cred_table.add_column("Count", justify="right")
    for row in top_creds:
        cred_table.add_row(row[0], row[1], str(row[2]))

    geo_table = Table(title="Top Origins", box=box.SIMPLE, expand=True)
    geo_table.add_column("Country")
    geo_table.add_column("Sessions", justify="right")
    for row in geo:
        geo_table.add_row(row[0] or "Unknown", str(row[1]))

    intent_table = Table(title="Post-Auth Intent", box=box.SIMPLE, expand=True)
    intent_table.add_column("Intent")
    intent_table.add_column("Count", justify="right")
    for row in intents:
        intent_table.add_row(row[0], str(row[1]))

    layout = Layout()
    layout.split_row(
        Layout(Panel(session_table, title="HoneyTrap Logger"), name="left"),
        Layout(name="right"),
    )
    layout["right"].split_column(
        Layout(Panel(cred_table)),
        Layout(Panel(geo_table)),
        Layout(Panel(intent_table)),
    )
    return layout


def run_dashboard():
    try:
        with Live(build_dashboard(), refresh_per_second=1, screen=True) as live:
            while True:
                time.sleep(1)
                live.update(build_dashboard())
    except KeyboardInterrupt:
        pass
