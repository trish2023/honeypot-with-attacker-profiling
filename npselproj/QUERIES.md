# HoneyTrap Logger — Database Query Reference

All queries run from the project folder (`C:\NPS\npselproj`) using PowerShell.

```powershell
cd C:\NPS\npselproj
```

> **Note:** `honeytrap.db` is created when `python web.py` (or `python main.py`) runs and attack traffic has been captured. If the file is missing, start the server and use **BOT SWARM** or **DEMO MODE** on the dashboard to generate data.

---

## Column Reference

| Table | Key columns |
|-------|-------------|
| `sessions` | `ip`, `protocol`, `country`, `city`, `classification`, `lat`, `lon`, `start_time` |
| `attempts` | `username`, `password`, `delay_ms`, `is_default` (0/1), `is_common` (0/1) |
| `shell_commands` | `command`, `intent_tag` |

- **`is_default = 1`** — username+password pair matched `data/default_creds.txt`
- **`is_common = 1`** — password alone matched `data/common_passwords.txt`
- **`delay_ms`** — milliseconds since previous attempt in the same session (`NULL` on first attempt)

---

## 1. Overview — row counts

```powershell
python -c "import sqlite3; c=sqlite3.connect('honeytrap.db'); print('sessions', c.execute('SELECT COUNT(*) FROM sessions').fetchone()[0]); print('attempts', c.execute('SELECT COUNT(*) FROM attempts').fetchone()[0]); print('shell_commands', c.execute('SELECT COUNT(*) FROM shell_commands').fetchone()[0])"
```

---

## 2. All sessions

```powershell
python -c "import sqlite3; c=sqlite3.connect('honeytrap.db'); print('--- sessions ---'); [print(r) for r in c.execute('SELECT session_id, ip, port, protocol, country, city, classification, lat, lon, start_time FROM sessions ORDER BY start_time DESC')]"
```

---

## 3. Recent sessions (last 20)

```powershell
python -c "import sqlite3; c=sqlite3.connect('honeytrap.db'); [print(r) for r in c.execute('SELECT ip, protocol, country, city, classification, lat, lon, start_time FROM sessions ORDER BY start_time DESC LIMIT 20')]"
```

---

## 4. Bot vs human breakdown

```powershell
python -c "import sqlite3; c=sqlite3.connect('honeytrap.db'); print('--- classification ---'); [print(r) for r in c.execute('SELECT classification, COUNT(*) FROM sessions GROUP BY classification')]"
```

---

## 5. Sessions by country

```powershell
python -c "import sqlite3; c=sqlite3.connect('honeytrap.db'); print('--- origins ---'); [print(r) for r in c.execute('SELECT country, COUNT(*) FROM sessions GROUP BY country ORDER BY COUNT(*) DESC')]"
```

---

## 6. All attempts (raw)

```powershell
python -c "import sqlite3; c=sqlite3.connect('honeytrap.db'); print('--- attempts ---'); [print(r) for r in c.execute('SELECT attempt_id, session_id, username, password, timestamp, delay_ms, is_default, is_common FROM attempts ORDER BY attempt_id DESC')]"
```

---

## 7. Attempts with enrichment — joined (from PRD Section 10)

```powershell
python -c "import sqlite3; c=sqlite3.connect('honeytrap.db'); print('--- attempts + enrichment ---'); [print(r) for r in c.execute('SELECT s.ip, s.country, s.protocol, s.classification, a.username, a.password, a.delay_ms, a.is_default, a.is_common FROM sessions s JOIN attempts a ON s.session_id = a.session_id ORDER BY a.timestamp DESC')]"
```

---

## 8. Default credentials only (`is_default = 1`)

```powershell
python -c "import sqlite3; c=sqlite3.connect('honeytrap.db'); print('--- default creds ---'); [print(r) for r in c.execute('SELECT s.ip, a.username, a.password FROM attempts a JOIN sessions s ON a.session_id = s.session_id WHERE a.is_default = 1 ORDER BY a.attempt_id DESC')]"
```

---

## 9. Common passwords only (`is_common = 1`)

```powershell
python -c "import sqlite3; c=sqlite3.connect('honeytrap.db'); print('--- common passwords ---'); [print(r) for r in c.execute('SELECT s.ip, a.username, a.password FROM attempts a JOIN sessions s ON a.session_id = s.session_id WHERE a.is_common = 1 ORDER BY a.attempt_id DESC')]"
```

---

## 10. Top credentials — most tried pairs

```powershell
python -c "import sqlite3; c=sqlite3.connect('honeytrap.db'); print('--- top credentials ---'); [print(r) for r in c.execute('SELECT username, password, COUNT(*) c FROM attempts GROUP BY username, password ORDER BY c DESC LIMIT 15')]"
```

---

## 11. All shell commands

```powershell
python -c "import sqlite3; c=sqlite3.connect('honeytrap.db'); print('--- shell commands ---'); [print(r) for r in c.execute('SELECT command_id, session_id, command, intent_tag, timestamp FROM shell_commands ORDER BY command_id DESC')]"
```

---

## 12. Post-auth intent summary (from PRD Section 10)

```powershell
python -c "import sqlite3; c=sqlite3.connect('honeytrap.db'); print('--- intent summary ---'); [print(r) for r in c.execute('SELECT intent_tag, COUNT(*) FROM shell_commands WHERE intent_tag IS NOT NULL GROUP BY intent_tag ORDER BY COUNT(*) DESC')]"
```

---

## 13. Full session drill-down

Replace `YOUR_SESSION_ID` with a session_id from query 2:

```powershell
python -c "import sqlite3; sid='YOUR_SESSION_ID'; c=sqlite3.connect('honeytrap.db'); print('SESSION', c.execute('SELECT * FROM sessions WHERE session_id=?',(sid,)).fetchone()); print('ATTEMPTS'); [print(r) for r in c.execute('SELECT username, password, delay_ms, is_default, is_common FROM attempts WHERE session_id=?',(sid,))]; print('SHELL'); [print(r) for r in c.execute('SELECT command, intent_tag FROM shell_commands WHERE session_id=?',(sid,))]"
```

---

## 14. Localhost / real traffic only

```powershell
python -c "import sqlite3; c=sqlite3.connect('honeytrap.db'); print('--- localhost sessions ---'); [print(r) for r in c.execute('SELECT ip, protocol, classification FROM sessions WHERE ip=\"127.0.0.1\"')]"
```

---

## 15. Sessions that reached the fake shell

```powershell
python -c "import sqlite3; c=sqlite3.connect('honeytrap.db'); print('--- breached sessions ---'); [print(r) for r in c.execute('SELECT DISTINCT s.ip, s.country, s.classification, COUNT(c.command_id) cmds FROM sessions s JOIN shell_commands c ON s.session_id = c.session_id GROUP BY s.session_id ORDER BY cmds DESC')]"
```

---

## Troubleshooting

| Error | Fix |
|-------|-----|
| `no such table` | DB is empty or you're in the wrong folder. Run `dir honeytrap.db` to confirm. |
| `database is locked` | Close DB Browser for SQLite if it has the file open, or briefly stop `web.py`. |
| Nothing printed | Tables are empty — use **BOT SWARM** or **DEMO MODE** on the dashboard first. |
