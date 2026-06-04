"""FastAPI application powering the web dashboard.

Responsibilities:
- Serve the single-page dashboard and its static assets.
- Expose a JSON snapshot of current state for initial page load.
- Stream live deltas (new sessions / attempts / shell commands + rolling stats)
  to all connected browsers over a WebSocket, driven by a background poller
  that reads new rows from SQLite.
- Provide control endpoints used by the in-page buttons: fire fabricated attack
  bursts, run a real attacker simulation, toggle continuous Demo Mode, and clear
  the database between demo runs.

All database reads share the honeypot's single connection and are guarded by the
same ``_db_lock`` used elsewhere, so the web layer never races the honeypot
writer threads.
"""

import asyncio
import threading
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from core.database import _db_lock, db_clear_all, get_db
from webapp import demo_generator
from webapp.demo_generator import demo_mode, fabricate_burst

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="HoneyTrap Logger")


# --------------------------------------------------------------------------- #
# Database read helpers (all guarded by _db_lock)
# --------------------------------------------------------------------------- #
def _aggregate_stats() -> dict:
    with _db_lock:
        db = get_db()
        total_sessions = db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        total_attempts = db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
        class_counts = dict(
            db.execute(
                "SELECT classification, COUNT(*) FROM sessions GROUP BY classification"
            ).fetchall()
        )
        breaches = db.execute(
            "SELECT COUNT(DISTINCT session_id) FROM shell_commands"
        ).fetchone()[0]
        countries = db.execute(
            "SELECT COUNT(DISTINCT country) FROM sessions "
            "WHERE country IS NOT NULL AND country != 'Unknown'"
        ).fetchone()[0]
    return {
        "sessions": total_sessions,
        "attempts": total_attempts,
        "bots": class_counts.get("bot", 0),
        "humans": class_counts.get("human", 0),
        "unknown": class_counts.get("unknown", 0),
        "breaches": breaches,
        "countries": countries,
    }


def _top_credentials(limit: int = 8) -> list:
    with _db_lock:
        rows = get_db().execute(
            "SELECT username, password, COUNT(*) c FROM attempts "
            "GROUP BY username, password ORDER BY c DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [{"username": u, "password": p, "count": c} for u, p, c in rows]


def _intent_breakdown() -> list:
    with _db_lock:
        rows = get_db().execute(
            "SELECT intent_tag, COUNT(*) c FROM shell_commands "
            "WHERE intent_tag IS NOT NULL GROUP BY intent_tag ORDER BY c DESC"
        ).fetchall()
    return [{"intent": t, "count": c} for t, c in rows]


def _top_origins(limit: int = 8) -> list:
    with _db_lock:
        rows = get_db().execute(
            "SELECT country, COUNT(*) c FROM sessions "
            "WHERE country IS NOT NULL AND country != 'Unknown' "
            "GROUP BY country ORDER BY c DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [{"country": c or "Unknown", "count": n} for c, n in rows]


def _session_markers(limit: int = 400) -> list:
    with _db_lock:
        rows = get_db().execute(
            "SELECT session_id, ip, country, city, lat, lon, protocol, classification "
            "FROM sessions WHERE lat IS NOT NULL ORDER BY start_time DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        {
            "session_id": r[0], "ip": r[1], "country": r[2], "city": r[3],
            "lat": r[4], "lon": r[5], "protocol": r[6], "classification": r[7],
        }
        for r in rows
    ]


def _recent_events(limit: int = 50) -> list:
    with _db_lock:
        db = get_db()
        attempts = db.execute(
            "SELECT a.timestamp, s.ip, s.country, a.username, a.password, "
            "a.is_default, a.is_common, s.classification, s.protocol "
            "FROM attempts a JOIN sessions s ON a.session_id = s.session_id "
            "ORDER BY a.attempt_id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        commands = db.execute(
            "SELECT c.timestamp, s.ip, s.country, c.command, c.intent_tag "
            "FROM shell_commands c JOIN sessions s ON c.session_id = s.session_id "
            "ORDER BY c.command_id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    events = []
    for r in attempts:
        events.append({
            "kind": "attempt", "ts": r[0], "ip": r[1], "country": r[2],
            "username": r[3], "password": r[4], "is_default": r[5],
            "is_common": r[6], "classification": r[7], "protocol": r[8],
        })
    for r in commands:
        events.append({
            "kind": "command", "ts": r[0], "ip": r[1], "country": r[2],
            "command": r[3], "intent_tag": r[4],
        })
    events.sort(key=lambda e: e["ts"], reverse=True)
    return events[:limit]


def _session_detail(session_id: str) -> dict:
    with _db_lock:
        db = get_db()
        s = db.execute(
            "SELECT session_id, ip, port, protocol, country, city, "
            "start_time, classification, lat, lon FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if not s:
            return {}
        attempts = db.execute(
            "SELECT username, password, timestamp, delay_ms, is_default, is_common "
            "FROM attempts WHERE session_id = ? ORDER BY attempt_id",
            (session_id,),
        ).fetchall()
        commands = db.execute(
            "SELECT command, timestamp, intent_tag FROM shell_commands "
            "WHERE session_id = ? ORDER BY command_id",
            (session_id,),
        ).fetchall()
    return {
        "session": {
            "session_id": s[0], "ip": s[1], "port": s[2], "protocol": s[3],
            "country": s[4], "city": s[5], "start_time": s[6],
            "classification": s[7], "lat": s[8], "lon": s[9],
        },
        "attempts": [
            {"username": a[0], "password": a[1], "timestamp": a[2],
             "delay_ms": a[3], "is_default": a[4], "is_common": a[5]}
            for a in attempts
        ],
        "commands": [
            {"command": c[0], "timestamp": c[1], "intent_tag": c[2]}
            for c in commands
        ],
    }


def _full_snapshot() -> dict:
    return {
        "stats": _aggregate_stats(),
        "markers": _session_markers(),
        "events": _recent_events(),
        "top_credentials": _top_credentials(),
        "intents": _intent_breakdown(),
        "origins": _top_origins(),
        "demo_running": demo_mode.running,
    }


# --------------------------------------------------------------------------- #
# WebSocket hub + live poller
# --------------------------------------------------------------------------- #
class Hub:
    def __init__(self):
        self.active: set[WebSocket] = set()
        self.loop: asyncio.AbstractEventLoop | None = None

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.add(ws)

    def disconnect(self, ws: WebSocket):
        self.active.discard(ws)

    async def broadcast(self, message: dict):
        for ws in list(self.active):
            try:
                await ws.send_json(message)
            except Exception:
                self.disconnect(ws)

    def broadcast_threadsafe(self, message: dict):
        if self.loop is not None:
            asyncio.run_coroutine_threadsafe(self.broadcast(message), self.loop)


hub = Hub()

# Poller cursor state.
_cursor = {"session_rowid": 0, "attempt_id": 0, "command_id": 0}


def _poll_deltas() -> list[dict]:
    """Read rows newer than the last seen cursors and return a list of
    broadcast messages. Runs in a threadpool (sync DB access)."""
    messages: list[dict] = []
    with _db_lock:
        db = get_db()
        new_sessions = db.execute(
            "SELECT rowid, session_id, ip, country, city, lat, lon, protocol, classification "
            "FROM sessions WHERE rowid > ? ORDER BY rowid LIMIT 300",
            (_cursor["session_rowid"],),
        ).fetchall()
        new_attempts = db.execute(
            "SELECT a.attempt_id, a.session_id, a.username, a.password, a.is_default, "
            "a.is_common, a.delay_ms, a.timestamp, s.ip, s.country, s.classification, s.protocol "
            "FROM attempts a JOIN sessions s ON a.session_id = s.session_id "
            "WHERE a.attempt_id > ? ORDER BY a.attempt_id LIMIT 400",
            (_cursor["attempt_id"],),
        ).fetchall()
        new_commands = db.execute(
            "SELECT c.command_id, c.session_id, c.command, c.intent_tag, c.timestamp, s.ip, s.country "
            "FROM shell_commands c JOIN sessions s ON c.session_id = s.session_id "
            "WHERE c.command_id > ? ORDER BY c.command_id LIMIT 400",
            (_cursor["command_id"],),
        ).fetchall()

    for r in new_sessions:
        _cursor["session_rowid"] = max(_cursor["session_rowid"], r[0])
        if r[5] is None:  # no coordinates -> not plottable (e.g. localhost)
            continue
        messages.append({"type": "session", "data": {
            "session_id": r[1], "ip": r[2], "country": r[3], "city": r[4],
            "lat": r[5], "lon": r[6], "protocol": r[7], "classification": r[8],
        }})
    for r in new_attempts:
        _cursor["attempt_id"] = max(_cursor["attempt_id"], r[0])
        messages.append({"type": "attempt", "data": {
            "session_id": r[1], "username": r[2], "password": r[3],
            "is_default": r[4], "is_common": r[5], "delay_ms": r[6],
            "ts": r[7], "ip": r[8], "country": r[9],
            "classification": r[10], "protocol": r[11],
        }})
    for r in new_commands:
        _cursor["command_id"] = max(_cursor["command_id"], r[0])
        messages.append({"type": "command", "data": {
            "session_id": r[1], "command": r[2], "intent_tag": r[3],
            "ts": r[4], "ip": r[5], "country": r[6],
        }})

    stats = _aggregate_stats()
    messages.append({"type": "stats", "data": {
        "stats": stats,
        "new_attempts": len(new_attempts),
        "top_credentials": _top_credentials(),
        "intents": _intent_breakdown(),
        "origins": _top_origins(),
        "demo_running": demo_mode.running,
    }})
    return messages


async def _poller():
    loop = asyncio.get_running_loop()
    while True:
        try:
            messages = await loop.run_in_executor(None, _poll_deltas)
            for msg in messages:
                await hub.broadcast(msg)
        except Exception:
            pass
        await asyncio.sleep(0.7)


@app.on_event("startup")
async def _on_startup():
    hub.loop = asyncio.get_running_loop()
    asyncio.create_task(_poller())


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/snapshot")
def snapshot():
    return JSONResponse(_full_snapshot())


@app.get("/api/session/{session_id}")
def session_detail(session_id: str):
    return JSONResponse(_session_detail(session_id))


def _launch(count: int, profile: str, spacing: float):
    threading.Thread(
        target=fabricate_burst,
        kwargs={"count": count, "profile": profile, "spacing": spacing},
        daemon=True,
    ).start()


@app.post("/api/attack/bot")
def attack_bot():
    _launch(count=12, profile="bot", spacing=0.15)
    return {"ok": True, "launched": "bot swarm"}


@app.post("/api/attack/human")
def attack_human():
    _launch(count=5, profile="human", spacing=0.3)
    return {"ok": True, "launched": "slow humans"}


@app.post("/api/attack/swarm")
def attack_swarm():
    _launch(count=45, profile="bot", spacing=0.06)
    return {"ok": True, "launched": "mega swarm"}


@app.post("/api/attack/custom")
def attack_custom(count: int = 10, profile: str = "bot", spacing: float = 0.15):
    profile = "human" if profile == "human" else "bot"
    _launch(count=count, profile=profile, spacing=max(0.0, spacing))
    return {"ok": True, "launched": f"{count} x {profile}"}


@app.post("/api/attack/real")
def attack_real(profile: str = "bot"):
    """Run the real attacker_sim against the live honeypot (authentic traffic).
    Localhost won't geolocate, so these appear in the feed but not on the map."""
    try:
        import attacker_sim
    except Exception as exc:  # pragma: no cover
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)
    fn = attacker_sim.simulate_human if profile == "human" else attacker_sim.simulate_bot
    threading.Thread(target=fn, daemon=True).start()
    return {"ok": True, "launched": f"real {profile} via attacker_sim"}


@app.post("/api/demo/start")
def demo_start():
    demo_mode.start()
    return {"ok": True, "running": demo_mode.running}


@app.post("/api/demo/stop")
def demo_stop():
    demo_mode.stop()
    return {"ok": True, "running": demo_mode.running}


@app.get("/api/demo/status")
def demo_status():
    return {"running": demo_mode.running}


@app.post("/api/clear")
def clear():
    demo_mode.stop()
    db_clear_all()
    _cursor["session_rowid"] = 0
    _cursor["attempt_id"] = 0
    _cursor["command_id"] = 0
    hub.broadcast_threadsafe({"type": "clear", "data": {}})
    return {"ok": True}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await hub.connect(ws)
    try:
        await ws.send_json({"type": "snapshot", "data": _full_snapshot()})
        while True:
            # We don't expect client messages; this keeps the socket open and
            # detects disconnects.
            await ws.receive_text()
    except WebSocketDisconnect:
        hub.disconnect(ws)
    except Exception:
        hub.disconnect(ws)


# Static assets (js/css). Mounted last so it doesn't shadow API routes.
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
