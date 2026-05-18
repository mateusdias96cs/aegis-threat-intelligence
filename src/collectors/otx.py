import os
import requests
from datetime import date

BASE_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

TYPE_MAP = {
    "IPv4": "ip",
    "domain": "domain",
    "hostname": "domain",
    "FileHash-MD5": "hash",
    "FileHash-SHA256": "hash",
    "URL": "url",
}


def collect() -> list[dict]:
    api_key = os.getenv("OTX_API_KEY")
    if not api_key:
        print("[otx] OTX_API_KEY is not set")
        return []

    headers = {"X-OTX-API-KEY": api_key}
    today = date.today().isoformat()
    iocs = []
    url = BASE_URL

    while url:
        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as e:
            print(f"[otx] failed to fetch pulses: {e}")
            break

        for pulse in data.get("results", []):
            pulse_name = pulse.get("name") or ""
            pulse_created = (pulse.get("created") or "")[:10] or None

            for indicator in pulse.get("indicators", []):
                otx_type = indicator.get("type")
                mapped_type = TYPE_MAP.get(otx_type)
                if mapped_type is None:
                    continue

                value = indicator.get("indicator")
                if not value:
                    continue

                iocs.append({
                    "type": mapped_type,
                    "value": value,
                    "source": "AlienVault-OTX",
                    "description": pulse_name,
                    "first_seen": pulse_created,
                    "last_seen": today,
                    "severity": "HIGH",
                    "country": None,
                    "abuse_score": None,
                })

        url = data.get("next")

    return iocs
