import requests
from datetime import date

# emerging-Block-IPs.txt virou ~todo CIDR (netblocks Spamhaus/DROP), que este
# collector por-IP não expande. compromised-ips.txt traz IPs INDIVIDUAIS de hosts
# comprometidos — o sinal por-IP que de fato alimenta a correlação do AEGIS.
ENDPOINT = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
MAX_IPS = 10000


def collect() -> list[dict]:
    today = date.today().isoformat()
    try:
        response = requests.get(ENDPOINT, timeout=30)
        response.raise_for_status()
        content = response.text
    except Exception as e:
        print(f"[emerging_threats] Error fetching feed: {e}")
        return []

    iocs = []
    try:
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Skip CIDR ranges — process plain IPs only
            if "/" in line:
                continue
            iocs.append({
                "type": "ip",
                "value": line,
                "source": "EmergingThreats",
                "severity": "HIGH",
                "description": "Emerging Threats — compromised IPs",
                "first_seen": today,
                "last_seen": today,
                "country": None,
                "abuse_score": None,
                "mitre_technique_id": None,
                "mitre_tactic": None,
                "confidence_score": None,
            })
            if len(iocs) >= MAX_IPS:
                break
    except Exception as e:
        print(f"[emerging_threats] Error parsing feed: {e}")
        return []

    print(f"[emerging_threats] {len(iocs)} IPs collected")
    return iocs
