"""Real-time single-IP reputation lookup (GreyNoise Community API + GeoIP2).

Used on demand by the Kill Chain / campaign views, not by the bulk pipeline.
"""

import os
import time
import requests

GREYNOISE_COMMUNITY_ENDPOINT = "https://api.greynoise.io/v3/community/{ip}"

_lookup_cache: dict = {}
_CACHE_TTL = 3600  # 1 hour

# GreyNoise classification → synthetic abuse_score
_SCORE_MAP = {"malicious": 85, "suspicious": 60, "benign": 5, "unknown": 20}


def _geoip_country(ip: str) -> str | None:
    db_path = os.getenv("MAXMIND_DB_PATH")
    if not db_path:
        return None
    try:
        import geoip2.database
        with geoip2.database.Reader(db_path) as reader:
            return reader.country(ip).country.iso_code
    except Exception:
        return None


def lookup_ip(ip: str) -> dict:
    """Real-time single-IP lookup via GreyNoise Community API + GeoIP2. 1-hour in-memory cache."""
    now = time.time()
    cached = _lookup_cache.get(ip)
    if cached and (now - cached["cached_at"]) < _CACHE_TTL:
        result = cached["result"].copy()
        result["_from_cache"] = True
        return result

    base: dict = {
        "ip": ip,
        "abuse_score": None,
        "country": _geoip_country(ip),
        "isp": None,
        "domain": None,
        "total_reports": None,
        "last_reported": None,
        "is_whitelisted": None,
        "usage_type": None,
        "source": "GreyNoise-Community",
        "_from_cache": False,
        "abuse_categories": None,
        "noise": None,
        "riot": None,
        "classification": None,
        "name": None,
    }

    try:
        response = requests.get(
            GREYNOISE_COMMUNITY_ENDPOINT.format(ip=ip),
            headers={"Accept": "application/json"},
            timeout=10,
        )

        if response.status_code == 404:
            _lookup_cache[ip] = {"result": base.copy(), "cached_at": now}
            return base

        if response.status_code == 429:
            base["error"] = "GreyNoise rate limit exceeded"
            return base

        response.raise_for_status()
        data = response.json()

        classification = data.get("classification")
        noise = data.get("noise", False)
        riot = data.get("riot", False)

        score = _SCORE_MAP.get(classification, 20)
        if noise and classification != "benign":
            score = min(100, score + 10)

        result = {
            **base,
            "abuse_score": score,
            "last_reported": data.get("last_seen"),
            "is_whitelisted": riot,
            "noise": noise,
            "riot": riot,
            "classification": classification,
            "name": data.get("name"),
        }

        _lookup_cache[ip] = {"result": result.copy(), "cached_at": now}
        return result

    except requests.RequestException as e:
        base["error"] = str(e)
        return base
