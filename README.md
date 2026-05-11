# Adaptive SSH/FTP Honeypot

A Python honeypot project for capturing and enriching attacker login attempts. The current implementation includes SQLite logging, enrichment helpers, tarpitting, a fake shell emulator, and a raw TCP SSH honeypot.

## Features

- SQLite storage in `honeypot.db`
- SSH attempt capture on port `2222`
- GeoIP lookup with MaxMind `GeoLite2-City.mmdb`
- Credential categorization using default credentials and common passwords
- Timing-based behavior classification
- Basic tool fingerprinting
- Escalating tarpit delays
- Fake post-auth shell session capture

## Project Files

- `db.py` - SQLite schema and query helpers
- `enrichment.py` - GeoIP lookup, credential tagging, behavior classification, and fingerprinting
- `tarpit.py` - delay calculation and sleep helper
- `shell_emulator.py` - fake interactive shell for accepted sessions
- `ssh_server.py` - raw TCP SSH honeypot listener
- `test_enrichment.py` - simple enrichment test script

## Data Files

Create a `data/` directory with these optional files:

- `data/GeoLite2-City.mmdb` - MaxMind GeoLite2 city database
- `data/default_creds.json` - list of default credential objects
- `data/common_passwords.txt` - one common password per line

Example `default_creds.json`:

```json
[
  {
    "username": "admin",
    "password": "admin"
  },
  {
    "username": "root",
    "password": "toor"
  }
]
```

If these files are missing, the enrichment functions fall back to safe defaults.

## Usage

Initialize the database:

```powershell
python -c "from db import init_db; init_db()"
```

Start the SSH honeypot:

```powershell
python -c "from ssh_server import SSHHoneypot; SSHHoneypot().start()"
```

The SSH honeypot listens on `0.0.0.0:2222`.

## Requirements

- Python 3.10+
- `geoip2` for GeoIP lookup

Install optional GeoIP support:

```powershell
pip install geoip2
```

Most other functionality uses Python's standard library.
