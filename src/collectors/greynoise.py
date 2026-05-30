import os
import requests
from datetime import date

GNQL_ENDPOINT = "https://api.greynoise.io/v3/experimental/gnql/ip_list"
GNQL_QUERY = "malicious:true"
MAX_IPS = 5000


def collect() -> list[dict]:
    api_key = os.getenv("GREYNOISE_API_KEY")
    if not api_key:
        print("[greynoise] GREYNOISE_API_KEY not set — skipping bulk feed")
        return []

    today = date.today().isoformat()
    try:
        response = requests.get(
            GNQL_ENDPOINT,
            headers={"key": api_key, "Accept": "application/json"},
            params={"q": GNQL_QUERY, "size": MAX_IPS},
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"[greynoise] Error fetching bulk feed: {e}")
        return []

    ip_list = data.get("ip_list", [])
    if not isinstance(ip_list, list):
        print("[greynoise] Unexpected response format")
        return []

    iocs = []
    for ip in ip_list[:MAX_IPS]:
        if not ip or not isinstance(ip, str):
            continue
        iocs.append({
            "type": "ip",
            "value": ip.strip(),
            "source": "GreyNoise",
            "severity": "HIGH",
            "description": "GreyNoise GNQL — malicious:true",
            "first_seen": today,
            "last_seen": today,
            "country": None,
            "abuse_score": None,
            "mitre_technique_id": None,
            "mitre_tactic": None,
            "confidence_score": None,
        })

    print(f"[greynoise] {len(iocs)} malicious IPs collected")
    return iocs
