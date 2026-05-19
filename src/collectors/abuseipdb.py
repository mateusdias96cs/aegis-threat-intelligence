import os
import time
import requests

ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

_EMPTY = {"abuse_score": None, "country": None}

# In-memory cache for lookup_ip results; resets on server restart (intentional)
_lookup_cache: dict = {}
_CACHE_TTL = 3600  # 1 hour


def enrich(ip: str) -> dict:
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        print("[abuseipdb] ABUSEIPDB_API_KEY is not set")
        return _EMPTY.copy()

    try:
        response = requests.get(
            ENDPOINT,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=30,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        return {
            "abuse_score": data.get("abuseConfidenceScore"),
            "country": data.get("countryCode"),
        }
    except requests.RequestException as e:
        print(f"[abuseipdb] failed to enrich {ip}: {e}")
        return _EMPTY.copy()


def enrich_batch(iocs: list) -> list:
    for ioc in iocs:
        if ioc.get("type") == "ip" and ioc.get("value"):
            ip_val = ioc["value"].split(":")[0]
            ioc.update(enrich(ip_val))
    return iocs


def lookup_ip(ip: str) -> dict:
    """Real-time single-IP lookup with a 1-hour in-memory cache."""
    now = time.time()
    cached = _lookup_cache.get(ip)
    if cached and (now - cached["cached_at"]) < _CACHE_TTL:
        result = cached["result"].copy()
        result["_from_cache"] = True
        return result

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {
            "ip": ip,
            "abuse_score": None,
            "country": None,
            "isp": None,
            "domain": None,
            "total_reports": None,
            "last_reported": None,
            "is_whitelisted": None,
            "usage_type": None,
            "source": "AbuseIPDB-Live",
            "_from_cache": False,
            "error": "ABUSEIPDB_API_KEY is not set",
        }

    try:
        response = requests.get(
            ENDPOINT,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": False},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        result = {
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports"),
            "last_reported": data.get("lastReportedAt"),
            "is_whitelisted": data.get("isWhitelisted"),
            "usage_type": data.get("usageType"),
            "source": "AbuseIPDB-Live",
            "_from_cache": False,
        }
        _lookup_cache[ip] = {"result": result, "cached_at": now}
        return result
    except requests.RequestException as e:
        return {
            "ip": ip,
            "abuse_score": None,
            "country": None,
            "isp": None,
            "domain": None,
            "total_reports": None,
            "last_reported": None,
            "is_whitelisted": None,
            "usage_type": None,
            "source": "AbuseIPDB-Live",
            "_from_cache": False,
            "error": str(e),
        }
