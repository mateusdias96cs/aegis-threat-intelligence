import os
import requests

ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

_EMPTY = {"abuse_score": None, "country": None}


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
