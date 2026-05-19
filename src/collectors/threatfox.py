from dotenv import load_dotenv
from datetime import date
import os
import requests

load_dotenv()
API_KEY = os.getenv("THREATFOX_API_KEY", "")

ENDPOINT = "https://threatfox.abuse.ch/export/json/recent/"


def collect() -> list[dict]:
    headers = {"Auth-Key": API_KEY} if API_KEY else {}
    today = str(date.today())

    try:
        response = requests.get(ENDPOINT, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"[threatfox] Error collecting data: {e}")
        return []

    if not isinstance(data, dict):
        return []

    iocs = []
    for key, entry in data.items():
        if not isinstance(entry, dict):
            continue

        tf_type = entry.get("ioc_type", "")
        internal_type = "unknown"
        if "ip" in tf_type:
            internal_type = "ip"
        elif "domain" in tf_type:
            internal_type = "domain"
        elif "url" in tf_type:
            internal_type = "url"
        elif "hash" in tf_type or "md5" in tf_type or "sha" in tf_type:
            internal_type = "hash"

        if internal_type == "unknown":
            continue

        raw_first_seen = entry.get("first_seen", today)
        raw_str = str(raw_first_seen) if raw_first_seen else today
        first_seen = raw_str.split("T")[0] if "T" in raw_str else raw_str

        iocs.append({
            "type": internal_type,
            "value": entry.get("ioc_value"),
            "source": "ThreatFox",
            "severity": "HIGH",
            "description": f"Malware: {entry.get('malware_printable', 'Unknown')} - {entry.get('threat_type', '')}",
            "first_seen": first_seen,
            "last_seen": today,
            "country": None,
            "abuse_score": None,
        })

    return iocs
