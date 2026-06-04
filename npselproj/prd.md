# HoneyTrap Logger — Product Requirements Document

**Project:** HoneyTrap Logger  
**Type:** NPS Lab EL (Elective Lab) Project  
**Version:** 1.0  
**Status:** In Development

---

## 1. Overview

HoneyTrap Logger is a dual-protocol honeypot server that simulates SSH and FTP services to attract, log, and behaviourally analyse unauthorised access attempts in real time. Built entirely on raw TCP socket programming, the system provides security researchers and network administrators with actionable intelligence about attacker patterns, credential usage, and post-authentication intent — without exposing any real infrastructure.

### Goals

- Capture credential attempts across SSH and FTP protocols
- Classify attacker behaviour (bot vs. human) from timing patterns
- Waste attacker resources through adaptive tarpitting
- Reveal post-authentication intent via a fake interactive shell
- Display live attack data in a terminal dashboard

### Non-Goals

- This is not a real SSH/FTP server — no actual authentication or file access
- No network-level blocking or firewall integration
- No cloud deployment in v1

---

## 2. System Architecture

Two honeypot servers run concurrently as threads on the same machine.

```
┌─────────────────────────────────────────────┐
│                  Main Process               │
│                                             │
│   ┌──────────────┐    ┌──────────────────┐  │
│   │ SSH Honeypot │    │  FTP Honeypot    │  │
│   │  port 2222   │    │   port 2121      │  │
│   └──────┬───────┘    └────────┬─────────┘  │
│          │                     │             │
│   ┌──────▼─────────────────────▼──────────┐  │
│   │         Session Handler Thread        │  │
│   │  fingerprint → enrich → tarpit →      │  │
│   │  log → respond → (fake shell?)        │  │
│   └──────────────────┬────────────────────┘  │
│                      │                       │
│   ┌──────────────────▼────────────────────┐  │
│   │            SQLite Database            │  │
│   └───────────────────────────────────────┘  │
│                      │                       │
│   ┌──────────────────▼────────────────────┐  │
│   │         Rich Terminal Dashboard       │  │
│   └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

| Service | Port | Protocol Simulated |
|---|---|---|
| SSH Honeypot | 2222 | SSH-2.0 banner + auth |
| FTP Honeypot | 2121 | FTP 220/331/530 flow |

---

## 3. Technology Stack

| Layer | Technology |
|---|---|
| Core networking | Python `socket`, `threading` |
| Data storage | SQLite via `sqlite3` |
| GeoIP resolution | `geoip2` + MaxMind GeoLite2 DB |
| Tarpitting | `time.sleep()` with exponential backoff |
| Dashboard UI | `rich` |
| Credential lists | Local flat files (default creds + rockyou top-1000) |
| Protocol simulation | Custom SSH banner + FTP state machine over raw TCP |

---

## 4. Database Schema

Two tables. All data is written before a response is issued to the attacker.

```sql
CREATE TABLE sessions (
    session_id    TEXT PRIMARY KEY,
    ip            TEXT NOT NULL,
    port          INTEGER NOT NULL,
    protocol      TEXT NOT NULL,          -- 'SSH' or 'FTP'
    country       TEXT,
    city          TEXT,
    start_time    REAL NOT NULL,          -- unix timestamp
    classification TEXT                   -- 'bot' | 'human' | 'unknown'
);

CREATE TABLE attempts (
    attempt_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL,
    username      TEXT NOT NULL,
    password      TEXT NOT NULL,
    timestamp     REAL NOT NULL,          -- unix timestamp, microsecond precision
    delay_ms      REAL,                   -- ms since last attempt in this session
    is_default    INTEGER DEFAULT 0,      -- 1 if matches default creds list
    is_common     INTEGER DEFAULT 0,      -- 1 if matches top-1000 passwords
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE shell_commands (
    command_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL,
    command       TEXT NOT NULL,
    timestamp     REAL NOT NULL,
    intent_tag    TEXT,                   -- 'malware_download' | 'credential_harvesting' | etc.
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);
```

---

## 5. Core Modules

### 5.1 TCP Server Foundation

Both honeypots share the same socket setup pattern. Each accepted connection is dispatched to a handler thread immediately.

```python
import socket
import threading
import uuid
import time

def start_server(port, handler_fn):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(100)
    print(f"[*] Listening on port {port}")
    while True:
        conn, addr = server.accept()
        session_id = str(uuid.uuid4())
        t = threading.Thread(
            target=handler_fn,
            args=(conn, addr, session_id),
            daemon=True
        )
        t.start()
```

**Entry point — run both servers simultaneously:**

```python
if __name__ == "__main__":
    threading.Thread(target=start_server, args=(2222, handle_ssh), daemon=True).start()
    threading.Thread(target=start_server, args=(2121, handle_ftp), daemon=True).start()

    # Keep main thread alive, hand off to dashboard
    run_dashboard()
```

---

### 5.2 SSH Honeypot Handler

SSH uses a banner exchange followed by a fake username/password prompt. No real cryptographic negotiation is performed — the server drops to a plaintext auth simulation after the banner.

```python
def handle_ssh(conn, addr, session_id):
    ip, port = addr
    db_insert_session(session_id, ip, port, 'SSH')

    try:
        # Step 1: Send SSH identification banner
        conn.send(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")

        # Step 2: Read client banner (discard — we don't do real key exchange)
        conn.recv(1024)

        # Step 3: Fake auth prompt loop
        attempt_count = 0
        last_attempt_time = None
        delay = 0

        while attempt_count < 6:
            conn.send(b"login: ")
            username = conn.recv(256).decode(errors='ignore').strip()
            if not username:
                break

            conn.send(b"password: ")
            password = conn.recv(256).decode(errors='ignore').strip()
            if not password:
                break

            now = time.time()
            delay_ms = (now - last_attempt_time) * 1000 if last_attempt_time else None
            last_attempt_time = now

            is_default, is_common = enrich_credentials(username, password)
            db_insert_attempt(session_id, username, password, now, delay_ms, is_default, is_common)

            # Tarpitting
            tarpit_delay = get_tarpit_delay(attempt_count)
            time.sleep(tarpit_delay)

            # Classification update
            if delay_ms and delay_ms < 500:
                db_update_classification(session_id, 'bot')
            elif delay_ms and delay_ms > 3000:
                db_update_classification(session_id, 'human')

            attempt_count += 1

            # Fake shell: grant access on 10% of sessions or after 3+ attempts
            if should_grant_access(session_id, attempt_count):
                conn.send(b"\r\nWelcome to Ubuntu 22.04 LTS\r\n$ ")
                handle_fake_shell(conn, session_id)
                break
            else:
                conn.send(b"Permission denied, please try again.\r\n")

    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        conn.close()
```

---

### 5.3 FTP Honeypot Handler

FTP is plaintext, so parsing `USER` and `PASS` commands is straightforward. The full 220/331/530 response flow is simulated.

```python
def handle_ftp(conn, addr, session_id):
    ip, port = addr
    db_insert_session(session_id, ip, port, 'FTP')

    try:
        # FTP greeting
        conn.send(b"220 FTP Server Ready (vsftpd 3.0.5)\r\n")

        attempt_count = 0
        last_attempt_time = None
        current_user = None

        while attempt_count < 6:
            data = conn.recv(1024).decode(errors='ignore').strip()
            if not data:
                break

            command = data[:4].upper()

            if command == "USER":
                current_user = data[5:].strip()
                conn.send(b"331 Please specify the password.\r\n")

            elif command == "PASS":
                password = data[5:].strip()
                now = time.time()
                delay_ms = (now - last_attempt_time) * 1000 if last_attempt_time else None
                last_attempt_time = now

                if current_user:
                    is_default, is_common = enrich_credentials(current_user, password)
                    db_insert_attempt(
                        session_id, current_user, password,
                        now, delay_ms, is_default, is_common
                    )

                    tarpit_delay = get_tarpit_delay(attempt_count)
                    time.sleep(tarpit_delay)

                    if delay_ms and delay_ms < 500:
                        db_update_classification(session_id, 'bot')
                    elif delay_ms and delay_ms > 3000:
                        db_update_classification(session_id, 'human')

                    attempt_count += 1

                    if should_grant_access(session_id, attempt_count):
                        conn.send(b"230 Login successful.\r\n")
                        handle_fake_shell(conn, session_id)
                        break
                    else:
                        conn.send(b"530 Login incorrect.\r\n")
                current_user = None

            elif command == "QUIT":
                conn.send(b"221 Goodbye.\r\n")
                break

            else:
                conn.send(b"530 Please login with USER and PASS.\r\n")

    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        conn.close()
```

---

### 5.4 Adaptive Tarpitting

Delay grows exponentially with each failure. Bot-classified sessions receive maximum delay immediately.

```python
def get_tarpit_delay(attempt_count: int) -> float:
    """
    Returns delay in seconds.
    attempt 0 → 1s
    attempt 1 → 3s
    attempt 2 → 8s
    attempt 3+ → 20s (cap)
    """
    delays = [1, 3, 8, 20]
    index = min(attempt_count, len(delays) - 1)
    return delays[index]
```

---

### 5.5 Credential Enrichment

Two flat files are loaded into memory at startup. Matching is O(1) via sets.

```
data/
  default_creds.txt     # format: username:password, one per line
  common_passwords.txt  # top 1000 passwords, one per line
```

```python
DEFAULT_CREDS = set()
COMMON_PASSWORDS = set()

def load_credential_lists():
    global DEFAULT_CREDS, COMMON_PASSWORDS
    with open("data/default_creds.txt") as f:
        for line in f:
            user, pwd = line.strip().split(":", 1)
            DEFAULT_CREDS.add((user, pwd))
    with open("data/common_passwords.txt") as f:
        COMMON_PASSWORDS = {line.strip() for line in f}

def enrich_credentials(username: str, password: str) -> tuple[int, int]:
    is_default = 1 if (username, password) in DEFAULT_CREDS else 0
    is_common = 1 if password in COMMON_PASSWORDS else 0
    return is_default, is_common
```

**Sample entries for `default_creds.txt`:**
```
admin:admin
root:toor
root:root
pi:raspberry
admin:password
ubnt:ubnt
guest:guest
```

---

### 5.6 GeoIP Enrichment

Uses MaxMind GeoLite2-City database (free, requires account registration at maxmind.com).

```python
import geoip2.database

_geoip_reader = None

def get_geoip_reader():
    global _geoip_reader
    if _geoip_reader is None:
        _geoip_reader = geoip2.database.Reader("data/GeoLite2-City.mmdb")
    return _geoip_reader

def lookup_ip(ip: str) -> tuple[str, str]:
    """Returns (country, city). Falls back to ('Unknown', 'Unknown')."""
    try:
        response = get_geoip_reader().city(ip)
        country = response.country.name or "Unknown"
        city = response.city.name or "Unknown"
        return country, city
    except Exception:
        return "Unknown", "Unknown"
```

The session record is updated after lookup:

```python
def db_insert_session(session_id, ip, port, protocol):
    country, city = lookup_ip(ip)
    conn = get_db()
    conn.execute(
        "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (session_id, ip, port, protocol, country, city, time.time(), 'unknown')
    )
    conn.commit()
```

---

### 5.7 Fake Shell

Approximately 10% of sessions, or any session with 3+ attempts, is granted fake access. The attacker lands in a simulated Linux shell. Every command is logged and tagged by intent.

```python
import random

def should_grant_access(session_id: str, attempt_count: int) -> bool:
    if attempt_count >= 3:
        return True
    return random.random() < 0.10

INTENT_TAGS = {
    "wget":          "malware_download",
    "curl":          "malware_download",
    "cat /etc/passwd": "credential_harvesting",
    "cat /etc/shadow": "credential_harvesting",
    "netstat":       "network_recon",
    "ifconfig":      "network_recon",
    "ip addr":       "network_recon",
    "ps aux":        "process_enum",
    "ps -ef":        "process_enum",
    "uname":         "system_info",
    "id":            "system_info",
    "crontab":       "persistence_attempt",
    "cron":          "persistence_attempt",
}

FAKE_RESPONSES = {
    "ls":      "Desktop  Documents  Downloads  Music  Pictures  Videos",
    "pwd":     "/home/user",
    "whoami":  "root",
    "id":      "uid=0(root) gid=0(root) groups=0(root)",
    "uname -a": "Linux ubuntu 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
    "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> inet 192.168.1.105",
    "netstat": "Active Internet connections\ntcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN",
    "ps aux":  "root         1  0.0  0.1  bash\nroot       123  0.0  0.2  sshd",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin",
    "wget":    "Connecting to attacker-c2... (simulated)",
    "curl":    "  % Total    % Received ... simulated transfer",
}

def handle_fake_shell(conn, session_id):
    conn.send(b"Last login: Mon Jan 15 09:32:11 2024\r\n$ ")

    while True:
        try:
            data = conn.recv(1024).decode(errors='ignore').strip()
        except Exception:
            break

        if not data:
            continue

        if data in ("exit", "logout", "quit"):
            conn.send(b"logout\r\n")
            break

        # Determine intent tag
        intent_tag = None
        for keyword, tag in INTENT_TAGS.items():
            if keyword in data.lower():
                intent_tag = tag
                break

        # Log the command
        db_insert_shell_command(session_id, data, time.time(), intent_tag)

        # Send fake response
        response = None
        for cmd_key, resp in FAKE_RESPONSES.items():
            if data.lower().startswith(cmd_key):
                response = resp
                break

        if response:
            conn.send(f"{response}\r\n$ ".encode())
        else:
            conn.send(f"bash: {data}: command not found\r\n$ ".encode())
```

---

### 5.8 SQLite Database Layer

Single shared connection with thread safety enabled.

```python
import sqlite3
import threading

_db_lock = threading.Lock()
_db_conn = None

def get_db() -> sqlite3.Connection:
    global _db_conn
    if _db_conn is None:
        _db_conn = sqlite3.connect("honeytrap.db", check_same_thread=False)
        _db_conn.execute("PRAGMA journal_mode=WAL")  # allows concurrent reads
        init_schema(_db_conn)
    return _db_conn

def init_schema(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            ip TEXT, port INTEGER, protocol TEXT,
            country TEXT, city TEXT,
            start_time REAL, classification TEXT
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
    """)
    conn.commit()

def db_insert_attempt(session_id, username, password, timestamp, delay_ms, is_default, is_common):
    with _db_lock:
        get_db().execute(
            "INSERT INTO attempts (session_id, username, password, timestamp, delay_ms, is_default, is_common) VALUES (?,?,?,?,?,?,?)",
            (session_id, username, password, timestamp, delay_ms, is_default, is_common)
        )
        get_db().commit()

def db_update_classification(session_id, classification):
    with _db_lock:
        get_db().execute(
            "UPDATE sessions SET classification=? WHERE session_id=?",
            (classification, session_id)
        )
        get_db().commit()

def db_insert_shell_command(session_id, command, timestamp, intent_tag):
    with _db_lock:
        get_db().execute(
            "INSERT INTO shell_commands (session_id, command, timestamp, intent_tag) VALUES (?,?,?,?)",
            (session_id, command, timestamp, intent_tag)
        )
        get_db().commit()
```

---

### 5.9 Behavioural Classification Engine

Classification is updated on every attempt within a session. Final classification reflects the majority signal.

| Condition | Label |
|---|---|
| Any delay < 500ms | `bot` (high confidence) |
| All delays > 3000ms | `human` |
| Mixed | `bot` (conservative default) |
| Single attempt, no prior delay | `unknown` |

```python
def classify_session(session_id: str) -> str:
    db = get_db()
    rows = db.execute(
        "SELECT delay_ms FROM attempts WHERE session_id=? AND delay_ms IS NOT NULL",
        (session_id,)
    ).fetchall()

    if not rows:
        return 'unknown'

    delays = [r[0] for r in rows]
    if any(d < 500 for d in delays):
        return 'bot'
    if all(d > 3000 for d in delays):
        return 'human'
    return 'bot'
```

---

### 5.10 Terminal Dashboard

Uses the `rich` library. Refreshes every second, reading live from SQLite.

```python
from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich import box
import time

def build_dashboard() -> Layout:
    db = get_db()

    # Active sessions in last 60s
    active = db.execute(
        "SELECT ip, protocol, classification, country FROM sessions WHERE start_time > ?",
        (time.time() - 60,)
    ).fetchall()

    # Top credentials
    top_creds = db.execute(
        "SELECT username, password, COUNT(*) as c FROM attempts GROUP BY username, password ORDER BY c DESC LIMIT 10"
    ).fetchall()

    # Geographic breakdown
    geo = db.execute(
        "SELECT country, COUNT(*) as c FROM sessions GROUP BY country ORDER BY c DESC LIMIT 5"
    ).fetchall()

    # Intent breakdown
    intents = db.execute(
        "SELECT intent_tag, COUNT(*) as c FROM shell_commands WHERE intent_tag IS NOT NULL GROUP BY intent_tag ORDER BY c DESC"
    ).fetchall()

    # Build tables
    session_table = Table(title="Active Sessions (last 60s)", box=box.SIMPLE)
    session_table.add_column("IP")
    session_table.add_column("Protocol")
    session_table.add_column("Classification")
    session_table.add_column("Country")
    for row in active:
        color = "red" if row[2] == "bot" else "yellow"
        session_table.add_row(row[0], row[1], f"[{color}]{row[2]}[/{color}]", row[3] or "?")

    cred_table = Table(title="Top Credentials", box=box.SIMPLE)
    cred_table.add_column("Username")
    cred_table.add_column("Password")
    cred_table.add_column("Count")
    for row in top_creds:
        cred_table.add_row(row[0], row[1], str(row[2]))

    geo_table = Table(title="Top Origins", box=box.SIMPLE)
    geo_table.add_column("Country")
    geo_table.add_column("Sessions")
    for row in geo:
        geo_table.add_row(row[0] or "Unknown", str(row[1]))

    intent_table = Table(title="Post-Auth Intent", box=box.SIMPLE)
    intent_table.add_column("Intent")
    intent_table.add_column("Count")
    for row in intents:
        intent_table.add_row(row[0], str(row[1]))

    layout = Layout()
    layout.split_row(
        Layout(Panel(session_table), name="left"),
        Layout(name="right")
    )
    layout["right"].split_column(
        Layout(Panel(cred_table)),
        Layout(Panel(geo_table)),
        Layout(Panel(intent_table))
    )
    return layout

def run_dashboard():
    with Live(build_dashboard(), refresh_per_second=1) as live:
        while True:
            time.sleep(1)
            live.update(build_dashboard())
```

---

## 6. Project File Structure

```
honeytrap-logger/
├── main.py                  # Entry point — starts both servers + dashboard
├── honeytrap.db             # SQLite database (auto-created)
├── servers/
│   ├── ssh_honeypot.py      # SSH handler
│   └── ftp_honeypot.py      # FTP handler
├── core/
│   ├── database.py          # SQLite layer + schema
│   ├── tarpitting.py        # Delay logic
│   ├── classification.py    # Bot/human engine
│   ├── enrichment.py        # GeoIP + credential matching
│   └── fake_shell.py        # Interactive shell + intent tagging
├── dashboard/
│   └── ui.py                # Rich terminal dashboard
└── data/
    ├── default_creds.txt    # username:password pairs
    ├── common_passwords.txt # top 1000 passwords
    └── GeoLite2-City.mmdb   # MaxMind GeoIP database
```

---

## 7. Installation & Setup

```bash
# 1. Clone / create project directory
mkdir honeytrap-logger && cd honeytrap-logger

# 2. Install Python dependencies
pip install geoip2 rich

# 3. Download MaxMind GeoLite2 database
# Register free at https://www.maxmind.com/en/geolite2/signup
# Download GeoLite2-City.mmdb and place in data/

# 4. Populate credential lists
# default_creds.txt — one username:password per line
# common_passwords.txt — one password per line (rockyou top-1000)

# 5. Run
python main.py
```

**Ports required:** 2222 (SSH), 2121 (FTP). No root required for ports > 1024.

---

## 8. Testing Without a Second Device

The entire system can be developed and demoed from a single machine.

**Manual testing with netcat:**
```bash
# Test SSH honeypot
nc localhost 2222

# Test FTP honeypot
nc localhost 2121
```

**Automated attacker simulation script:**
```python
# attacker_sim.py
import socket
import time

FTP_CREDS = [
    ("admin", "admin"),
    ("root", "toor"),
    ("pi", "raspberry"),
    ("user", "password123"),
]

def simulate_bot(delay=0.1):
    """Fast bot — should trigger bot classification"""
    for user, pwd in FTP_CREDS:
        s = socket.socket()
        s.connect(('127.0.0.1', 2121))
        s.recv(256)                              # read 220 greeting
        s.send(f"USER {user}\r\n".encode())
        s.recv(256)                              # read 331
        time.sleep(delay)
        s.send(f"PASS {pwd}\r\n".encode())
        resp = s.recv(256).decode()
        print(f"[{user}:{pwd}] → {resp.strip()}")
        s.close()
        time.sleep(delay)

def simulate_human(delay=4.0):
    """Slow human — should trigger human classification"""
    simulate_bot(delay=delay)

if __name__ == "__main__":
    print("=== Simulating bot ===")
    simulate_bot(delay=0.1)
    time.sleep(2)
    print("=== Simulating human ===")
    simulate_human(delay=4.0)
```

Run with: `python attacker_sim.py`

---

## 9. Deliverables Checklist

| Deliverable | Status |
|---|---|
| Dual-protocol honeypot (SSH + FTP over raw TCP) | Specified |
| Real-time terminal dashboard (`rich`) | Specified |
| SQLite database with enriched session logs | Specified |
| Behavioural classification engine (bot vs human) | Specified |
| Fake interactive shell with intent tagging | Specified |
| Adaptive tarpitting | Specified |
| GeoIP enrichment | Specified |
| Credential categorisation (default + common) | Specified |
| Project report with sample attack data | Pending |
| Single-machine simulation script | Specified |

---

## 10. Sample Attack Data Format

After a test run, query the database directly:

```sql
-- All attempts with enrichment
SELECT s.ip, s.country, s.protocol, s.classification,
       a.username, a.password, a.delay_ms, a.is_default, a.is_common
FROM sessions s JOIN attempts a ON s.session_id = a.session_id
ORDER BY a.timestamp DESC;

-- Post-auth intent summary
SELECT intent_tag, COUNT(*) FROM shell_commands
WHERE intent_tag IS NOT NULL
GROUP BY intent_tag;

-- Bot vs human breakdown
SELECT classification, COUNT(*) FROM sessions GROUP BY classification;
```