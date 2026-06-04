"""Geographic data for the dashboard map.

Provides a curated set of attack-origin countries (each with representative
coordinates and an ISO code), weighted toward regions that dominate real
honeypot telemetry, plus helpers to pick weighted random origins and fabricate
plausible public IP addresses for those origins. Used by the demo generator so
the world map and live feed look alive during a presentation.
"""

import random

# country -> (iso2, latitude, longitude, weight)
# Weight roughly mirrors the share of automated attack traffic seen by public
# honeypots; higher weight => picked more often.
COUNTRY_COORDS = {
    "China":          ("CN", 39.90, 116.40, 22),
    "Russia":         ("RU", 55.75, 37.62, 18),
    "United States":  ("US", 38.90, -77.04, 14),
    "Brazil":         ("BR", -15.79, -47.88, 9),
    "India":          ("IN", 28.61, 77.21, 9),
    "Vietnam":        ("VN", 21.03, 105.85, 6),
    "Indonesia":      ("ID", -6.21, 106.85, 5),
    "Iran":           ("IR", 35.69, 51.39, 5),
    "South Korea":    ("KR", 37.57, 126.98, 4),
    "Ukraine":        ("UA", 50.45, 30.52, 4),
    "Netherlands":    ("NL", 52.37, 4.90, 4),
    "Germany":        ("DE", 52.52, 13.40, 4),
    "France":         ("FR", 48.86, 2.35, 3),
    "Romania":        ("RO", 44.43, 26.10, 3),
    "Turkey":         ("TR", 39.93, 32.86, 3),
    "Nigeria":        ("NG", 9.08, 7.40, 3),
    "Mexico":         ("MX", 19.43, -99.13, 3),
    "Argentina":      ("AR", -34.60, -58.38, 2),
    "Egypt":          ("EG", 30.04, 31.24, 2),
    "Thailand":       ("TH", 13.76, 100.50, 2),
    "Pakistan":       ("PK", 33.69, 73.06, 2),
    "United Kingdom": ("GB", 51.51, -0.13, 2),
    "Poland":         ("PL", 52.23, 21.01, 2),
    "Italy":          ("IT", 41.90, 12.50, 2),
    "Spain":          ("ES", 40.42, -3.70, 2),
    "Canada":         ("CA", 45.42, -75.70, 2),
    "Japan":          ("JP", 35.68, 139.69, 2),
    "Colombia":       ("CO", 4.71, -74.07, 2),
    "South Africa":   ("ZA", -25.75, 28.19, 2),
    "Singapore":      ("SG", 1.35, 103.82, 2),
    "Bangladesh":     ("BD", 23.81, 90.41, 2),
    "Philippines":    ("PH", 14.60, 120.98, 2),
    "Taiwan":         ("TW", 25.03, 121.57, 2),
    "Saudi Arabia":   ("SA", 24.71, 46.68, 1),
    "Kazakhstan":     ("KZ", 51.17, 71.45, 1),
    "Australia":      ("AU", -35.28, 149.13, 1),
    "Sweden":         ("SE", 59.33, 18.07, 1),
    "Hong Kong":      ("HK", 22.32, 114.17, 1),
    "Israel":         ("IL", 31.77, 35.21, 1),
    "Chile":          ("CL", -33.45, -70.67, 1),
}

# Representative capital cities for nicer feed labels.
COUNTRY_CITY = {
    "China": "Beijing", "Russia": "Moscow", "United States": "Ashburn",
    "Brazil": "Brasilia", "India": "New Delhi", "Vietnam": "Hanoi",
    "Indonesia": "Jakarta", "Iran": "Tehran", "South Korea": "Seoul",
    "Ukraine": "Kyiv", "Netherlands": "Amsterdam", "Germany": "Frankfurt",
    "France": "Paris", "Romania": "Bucharest", "Turkey": "Ankara",
    "Nigeria": "Abuja", "Mexico": "Mexico City", "Argentina": "Buenos Aires",
    "Egypt": "Cairo", "Thailand": "Bangkok", "Pakistan": "Islamabad",
    "United Kingdom": "London", "Poland": "Warsaw", "Italy": "Rome",
    "Spain": "Madrid", "Canada": "Ottawa", "Japan": "Tokyo",
    "Colombia": "Bogota", "South Africa": "Pretoria", "Singapore": "Singapore",
    "Bangladesh": "Dhaka", "Philippines": "Manila", "Taiwan": "Taipei",
    "Saudi Arabia": "Riyadh", "Kazakhstan": "Astana", "Australia": "Canberra",
    "Sweden": "Stockholm", "Hong Kong": "Hong Kong", "Israel": "Jerusalem",
    "Chile": "Santiago",
}

_COUNTRIES = list(COUNTRY_COORDS.keys())
_WEIGHTS = [COUNTRY_COORDS[c][3] for c in _COUNTRIES]


def random_origin(jitter: float = 1.5):
    """Pick a weighted-random country and return a geo dict with slightly
    jittered coordinates so repeated picks from one country don't stack
    perfectly on top of each other on the map."""
    country = random.choices(_COUNTRIES, weights=_WEIGHTS, k=1)[0]
    iso, lat, lon, _w = COUNTRY_COORDS[country]
    return {
        "country": country,
        "city": COUNTRY_CITY.get(country, "Unknown"),
        "iso": iso,
        "lat": round(lat + random.uniform(-jitter, jitter), 4),
        "lon": round(lon + random.uniform(-jitter, jitter), 4),
    }


def random_public_ip() -> str:
    """Fabricate a plausible-looking public IPv4 address (avoids obvious
    private/reserved ranges)."""
    while True:
        a = random.randint(1, 223)
        if a in (10, 127, 169, 172, 192):
            continue
        return f"{a}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
