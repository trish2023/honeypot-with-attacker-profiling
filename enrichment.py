import json
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    import geoip2.database
except ImportError:
    geoip2 = None


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
GEOIP_DB_PATH = DATA_DIR / "GeoLite2-City.mmdb"
DEFAULT_CREDS_PATH = DATA_DIR / "default_creds.json"
COMMON_PASSWORDS_PATH = DATA_DIR / "common_passwords.txt"


def _unknown_location() -> dict[str, str | float]:
    return {
        "country": "Unknown",
        "city": "Unknown",
        "lat": 0.0,
        "lon": 0.0,
    }


'''def locate(ip: str) -> dict[str, str | float]:
    """Return GeoIP city details for an IP address."""
    if geoip2 is None or not GEOIP_DB_PATH.exists():
        return _unknown_location()

    try:
        with geoip2.database.Reader(str(GEOIP_DB_PATH)) as reader:
            response = reader.city(ip)
            return {
                "country": response.country.name or "Unknown",
                "city": response.city.name or "Unknown",
                "lat": float(response.location.latitude or 0.0),
                "lon": float(response.location.longitude or 0.0),
            }
    except Exception:
        return _unknown_location()'''



def _load_default_creds() -> set[tuple[str, str]]:
    try:
        with DEFAULT_CREDS_PATH.open("r", encoding="utf-8") as file:
            creds = json.load(file)
    except (OSError, json.JSONDecodeError):
        return set()

    return {
        (str(item.get("username", "")), str(item.get("password", "")))
        for item in creds
        if isinstance(item, dict)
    }


def _load_common_passwords() -> set[str]:
    try:
        with COMMON_PASSWORDS_PATH.open("r", encoding="utf-8") as file:
            return {line.strip() for line in file if line.strip()}
    except OSError:
        return set()


DEFAULT_CREDS = _load_default_creds()
COMMON_PASSWORDS = _load_common_passwords()


def categorize(username: str, password: str) -> str:
    """Classify a credential pair as default, common, or unknown."""
    if (username, password) in DEFAULT_CREDS:
        return "default"
    if password in COMMON_PASSWORDS:
        return "common"
    return "unknown"


def _timestamp_to_seconds(timestamp: Any) -> float | None:
    if isinstance(timestamp, datetime):
        return timestamp.timestamp()
    if isinstance(timestamp, (int, float)):
        return float(timestamp)
    if not isinstance(timestamp, str):
        return None

    normalized = timestamp.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized).timestamp()
    except ValueError:
        try:
            return float(normalized)
        except ValueError:
            return None


def classify_behavior(
    ip: str,
    timestamp: Any,
    attempt_times_dict: dict[str, list[Any]],
) -> str:
    """Classify behavior from the average timing gap between attempts."""
    attempt_times = attempt_times_dict.setdefault(ip, [])
    attempt_times.append(timestamp)

    parsed_times = [
        parsed
        for parsed in (_timestamp_to_seconds(item) for item in attempt_times)
        if parsed is not None
    ]
    if len(parsed_times) < 2:
        return "unknown"

    parsed_times.sort()
    gaps = [
        current - previous
        for previous, current in zip(parsed_times, parsed_times[1:])
        if current >= previous
    ]
    if not gaps:
        return "unknown"

    average_gap = sum(gaps) / len(gaps)
    if average_gap < 0.5:
        return "bot"
    if average_gap > 3:
        return "human"
    return "unknown"


def fingerprint_tool(banner_response: str | None, timing_gap: float) -> str:
    """Infer the scanner or brute-force tool from banner and timing signals."""
    if not isinstance(banner_response, str) or not banner_response.strip():
        return "Masscan"

    if timing_gap < 0.1:
        return "Hydra"
    if 0.1 <= timing_gap <= 0.3:
        return "Medusa"
    return "unknown"
