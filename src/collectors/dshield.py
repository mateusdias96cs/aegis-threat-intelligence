import math
import requests
from datetime import date

# SANS Internet Storm Center / DShield — top IPs atacantes observados por milhares
# de sensores de firewall no mundo. Diferente de uma blocklist, traz VOLUME real de
# ataques e as datas reais de primeiro/último evento — telemetria de ataque que de
# fato ocorreu, e independente das demais fontes (família honeypot/firewall).
# A API zera a resposta para limites grandes (>~500); 500 é o teto seguro.
ENDPOINT = "https://isc.sans.edu/api/sources/attacks/{limit}?json"
MAX_IPS = 500
# ISC pede um User-Agent identificável com contato.
HEADERS = {"User-Agent": "AEGIS-CTI/1.0 (+https://aegiscti.me)"}


def _attacks_to_score(attacks: int) -> int:
    """Mapeia o volume de ataques para um abuse_score discriminativo (0–100).

    Escala log — distingue um IP com 1 ataque (50) de um varredor massivo com
    10k+ ataques (100). É o sinal por-IP que faltava: substitui o carimbo HIGH
    fixo das blocklists por severidade derivada de evidência real.
    """
    if attacks <= 0:
        return 50
    return min(100, round(50 + 12.5 * math.log10(attacks)))


def collect() -> list[dict]:
    today = date.today().isoformat()
    try:
        response = requests.get(
            ENDPOINT.format(limit=MAX_IPS), headers=HEADERS, timeout=30
        )
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"[dshield] Error fetching feed: {e}")
        return []

    if not isinstance(data, list):
        print("[dshield] Unexpected response format")
        return []

    iocs = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        ip = (entry.get("ip") or "").strip()
        if not ip:
            continue

        try:
            attacks = int(entry.get("attacks") or 0)
        except (TypeError, ValueError):
            attacks = 0
        score = _attacks_to_score(attacks)

        # Datas REAIS do evento — alimentam a janela temporal de correlação
        # (que com first_seen=hoje das blocklists ficava sem sentido).
        first_seen = (entry.get("firstseen") or today)[:10]
        last_seen  = (entry.get("lastseen") or today)[:10]

        iocs.append({
            "type": "ip",
            "value": ip,
            "source": "DShield",
            "severity": "HIGH",  # refinada pelo classifier a partir do abuse_score
            "description": f"DShield/ISC — {attacks} ataques observados ({entry.get('count', 0)} reports)",
            "first_seen": first_seen,
            "last_seen": last_seen,
            "country": None,
            "abuse_score": score,
            "mitre_technique_id": None,
            "mitre_tactic": None,
            "confidence_score": None,
        })

    print(f"[dshield] {len(iocs)} attacking IPs collected")
    return iocs
