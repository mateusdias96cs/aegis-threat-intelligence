import os
import time
import requests
from datetime import date

ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
BLACKLIST_ENDPOINT = "https://api.abuseipdb.com/api/v2/blacklist"

# ── Quota diária AbuseIPDB (free tier: 1000 req/dia) ─────────────────────────
# Reserva 100 para lookups manuais no dashboard. Pipeline usa até 900/dia.
_DAILY_QUOTA = 900
_quota_state: dict = {"date": None, "used": 0}


def _quota_remaining() -> int:
    """Retorna quantas chamadas ainda podem ser feitas hoje pelo pipeline."""
    today = date.today().isoformat()
    if _quota_state["date"] != today:
        _quota_state["date"] = today
        _quota_state["used"] = 0
    return max(0, _DAILY_QUOTA - _quota_state["used"])


def _quota_consume(n: int = 1) -> None:
    """Registra n chamadas consumidas."""
    today = date.today().isoformat()
    if _quota_state["date"] != today:
        _quota_state["date"] = today
        _quota_state["used"] = 0
    _quota_state["used"] += n


def fetch_blacklist() -> list:
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        print("[abuseipdb] ABUSEIPDB_API_KEY is not set — skipping blacklist")
        return []

    today = date.today().isoformat()
    try:
        response = requests.get(
            BLACKLIST_ENDPOINT,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"limit": 10000, "confidenceMinimum": 75},
            timeout=30,
        )
        response.raise_for_status()
        entries = response.json().get("data", [])
    except Exception as e:
        print(f"[abuseipdb] fetch_blacklist error: {e}")
        return []

    iocs = []
    for entry in entries:
        ip = entry.get("ipAddress", "")
        if not ip:
            continue
        score = entry.get("abuseConfidenceScore", 0)
        iocs.append({
            "type": "ip",
            "value": ip,
            "source": "AbuseIPDB-Blacklist",
            "severity": "CRITICAL" if score >= 90 else "HIGH",
            "abuse_score": score,
            "country": entry.get("countryCode"),
            "description": f"AbuseIPDB blacklisted IP — confidence: {score}",
            "first_seen": today,
            "last_seen": today,
            "mitre_technique_id": None,
            "mitre_tactic": None,
            "confidence_score": None,
        })
    return iocs

_EMPTY = {"abuse_score": None, "country": None}

# In-memory cache for lookup_ip results; resets on server restart (intentional)
_lookup_cache: dict = {}
_CACHE_TTL = 3600  # 1 hour


def enrich(ip: str) -> dict:
    """Enriquece um único IP. Respeita quota diária do pipeline."""
    if _quota_remaining() <= 0:
        print(f"[abuseipdb] quota diária do pipeline esgotada — pulando {ip}")
        return _EMPTY.copy()

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        print("[abuseipdb] ABUSEIPDB_API_KEY is not set")
        return _EMPTY.copy()

    try:
        response = requests.get(
            ENDPOINT,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=30,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        _quota_consume()

        reports = data.get("reports", [])
        cats: dict[int, int] = {}
        for r in reports:
            for cat_id in r.get("categories", []):
                cats[cat_id] = cats.get(cat_id, 0) + 1

        return {
            "abuse_score": data.get("abuseConfidenceScore"),
            "country": data.get("countryCode"),
            "abuse_categories": cats if cats else None,
        }
    except requests.RequestException as e:
        print(f"[abuseipdb] failed to enrich {ip}: {e}")
        return _EMPTY.copy()


def enrich_batch(iocs: list) -> list:
    """
    Enriquece IPs com AbuseIPDB respeitando quota diária.
    Processa apenas type=ip. Para quando quota esgota.
    """
    ip_iocs = [ioc for ioc in iocs if ioc.get("type") == "ip" and ioc.get("value")]
    total = len(ip_iocs)
    remaining = _quota_remaining()

    if remaining <= 0:
        print(f"[abuseipdb] enrich_batch: quota esgotada — {total} IPs sem enriquecimento")
        return iocs

    to_enrich = ip_iocs[:remaining]
    skipped = total - len(to_enrich)

    print(f"[abuseipdb] enrich_batch: {len(to_enrich)} IPs a enriquecer, {skipped} pulados (quota), {remaining} restantes hoje")

    for ioc in to_enrich:
        ip_val = ioc["value"].split(":")[0]
        result = enrich(ip_val)
        ioc.update(result)

    print(f"[abuseipdb] enrich_batch: concluído. Quota restante: {_quota_remaining()}")
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
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        _reports = data.get("reports", [])
        _cats: dict[int, int] = {}
        for _r in _reports:
            for _cat_id in _r.get("categories", []):
                _cats[_cat_id] = _cats.get(_cat_id, 0) + 1

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
            "abuse_categories": _cats,
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
