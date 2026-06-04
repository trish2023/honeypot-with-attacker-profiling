"""Credential and GeoIP enrichment (PRD Sections 5.5 and 5.6).

Two flat files are loaded into memory at startup for O(1) credential matching.
GeoIP resolution uses the MaxMind GeoLite2-City database; if the database file
is missing or a lookup fails, it falls back to ('Unknown', 'Unknown').
"""

import geoip2.database

DEFAULT_CREDS = set()
COMMON_PASSWORDS = set()

DEFAULT_CREDS_PATH = "data/default_creds.txt"
COMMON_PASSWORDS_PATH = "data/common_passwords.txt"
GEOIP_DB_PATH = "data/GeoLite2-City.mmdb"

_geoip_reader = None


def load_credential_lists():
    """Load the default-credentials and common-password lists into memory.
    Called once at startup before any connections are accepted."""
    global DEFAULT_CREDS, COMMON_PASSWORDS
    creds = set()
    with open(DEFAULT_CREDS_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            user, pwd = line.split(":", 1)
            creds.add((user, pwd))
    DEFAULT_CREDS = creds

    with open(COMMON_PASSWORDS_PATH, encoding="utf-8") as f:
        COMMON_PASSWORDS = {line.strip() for line in f if line.strip()}

    print(
        f"[*] Loaded {len(DEFAULT_CREDS)} default creds, "
        f"{len(COMMON_PASSWORDS)} common passwords"
    )


def enrich_credentials(username: str, password: str) -> tuple[int, int]:
    is_default = 1 if (username, password) in DEFAULT_CREDS else 0
    is_common = 1 if password in COMMON_PASSWORDS else 0
    return is_default, is_common


def get_geoip_reader():
    global _geoip_reader
    if _geoip_reader is None:
        _geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
    return _geoip_reader


def lookup_ip(ip: str) -> tuple[str, str]:
    """Returns (country, city). Falls back to ('Unknown', 'Unknown') when the
    GeoLite2 database is absent or the IP cannot be resolved (e.g. private IPs)."""
    country, city, _lat, _lon = lookup_geo(ip)
    return country, city


def lookup_geo(ip: str):
    """Returns (country, city, lat, lon). Falls back to
    ('Unknown', 'Unknown', None, None) when the GeoLite2 database is absent or
    the IP cannot be resolved (e.g. private/localhost IPs)."""
    try:
        response = get_geoip_reader().city(ip)
        country = response.country.name or "Unknown"
        city = response.city.name or "Unknown"
        lat = response.location.latitude
        lon = response.location.longitude
        return country, city, lat, lon
    except Exception:
        return "Unknown", "Unknown", None, None
