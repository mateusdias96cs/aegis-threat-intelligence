import csv
import io
import requests
from datetime import date

ENDPOINT = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"


def collect() -> list[dict]:
    today = date.today().isoformat()

    try:
        response = requests.get(ENDPOINT, timeout=30)
        response.raise_for_status()
        content = response.text
    except Exception as e:
        print(f"[feodo] Error fetching feed: {e}")
        return []

    iocs = []
    try:
        lines = [line for line in content.splitlines() if line and not line.startswith("#")]
        reader = csv.DictReader(lines)
        for row in reader:
            dst_ip = row.get("dst_ip", "").strip()
            if not dst_ip:
                continue

            first_seen_utc = row.get("first_seen_utc", "").strip()
            c2_status = row.get("c2_status", "").strip()
            malware = row.get("malware", "").strip()

            first_seen = first_seen_utc.split(" ")[0] if first_seen_utc else today

            iocs.append({
                "type": "ip",
                "value": dst_ip,
                "source": "FeodoTracker",
                "severity": "CRITICAL" if c2_status == "online" else "HIGH",
                "description": f"Botnet C2 — {malware}",
                "first_seen": first_seen,
                "last_seen": today,
                "country": None,
                "abuse_score": None,
                "mitre_technique_id": "T1071",
                "mitre_tactic": "Command And Control",
                "confidence_score": None,
            })

    except Exception as e:
        print(f"[feodo] Error parsing feed: {e}")
        return []

    return iocs
