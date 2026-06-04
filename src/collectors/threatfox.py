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
    # O export agora mapeia cada id para uma LISTA de objetos ({id: [ {…} ]});
    # versões antigas mapeavam direto para um dict. Normaliza os dois formatos.
    for key, entries in data.items():
        if isinstance(entries, dict):
            entries = [entries]
        if not isinstance(entries, list):
            continue

        for entry in entries:
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

            raw_value = entry.get("ioc_value") or entry.get("ioc")
            if not raw_value:
                continue
            if internal_type == "ip":
                raw_value = raw_value.split(":")[0]

            # O campo virou first_seen_utc; mantém fallback para o nome antigo.
            raw_first_seen = entry.get("first_seen_utc") or entry.get("first_seen") or today
            raw_str = str(raw_first_seen) if raw_first_seen else today
            first_seen = raw_str.split("T")[0].split(" ")[0]

            iocs.append({
                "type": internal_type,
                "value": raw_value,
                "source": "ThreatFox",
                "severity": "HIGH",
                "description": f"Malware: {entry.get('malware_printable', 'Unknown')} - {entry.get('threat_type', '')}",
                "first_seen": first_seen,
                "last_seen": today,
                "country": None,
                "abuse_score": None,
            })

    return iocs
