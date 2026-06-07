"""IPsum collector — IPs aggregated across 30+ public blocklists."""

import requests
from datetime import date

# IPsum (stamparm/ipsum): feed diário que AGREGA 30+ blacklists públicas de IP e
# publica, por IP, o número de listas em que ele aparece (hit-count). Usar o IPsum
# em vez de ingerir cada lista isolada evita REDUNDÂNCIA — ele já deduplica todo o
# ecossistema (blocklist.de, CINS, GreenSnow, FireHOL, ET, etc.) num só lugar.
#
# Nível 3 = IP listado em >= 3 blacklists independentes: corte de baixo falso-
# positivo (quanto mais listas, menor a chance de FP). O hit-count vira sinal de
# FORÇA (abuse_score/T), não de corroboração (C) — a família é 'honeypot' no
# classifier, então concordar com DShield/ET não infla a confiança.
ENDPOINT = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
MIN_LISTS = 3
MAX_IPS = 20000
HEADERS = {"User-Agent": "AEGIS-CTI/1.0 (+https://aegiscti.me)"}


def _hits_to_score(hits: int) -> int:
    """Mapeia o nº de blacklists para um abuse_score discriminativo (0–100).

    3 listas → 70 (HIGH); cresce ~8/lista até saturar em 100 (>=6 listas →
    CRITICAL). Dá ao analista a confiança proporcional ao consenso entre fontes.
    """
    return min(100, 70 + (hits - 3) * 8)


def collect() -> list[dict]:
    """Collect malicious IPs from the IPsum aggregated feed.

    Keeps IPs listed in at least ``MIN_LISTS`` independent blocklists (a
    low-false-positive cut) and maps the hit-count to an abuse score.

    Returns:
        list[dict]: IOCs of type ``ip`` (up to ``MAX_IPS``). Empty on failure.
    """
    today = date.today().isoformat()
    try:
        response = requests.get(ENDPOINT, headers=HEADERS, timeout=30)
        response.raise_for_status()
        content = response.text
    except Exception as e:
        print(f"[ipsum] Error fetching feed: {e}")
        return []

    iocs = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        ip = parts[0]
        try:
            hits = int(parts[1]) if len(parts) > 1 else 1
        except (TypeError, ValueError):
            hits = 1

        if hits < MIN_LISTS:
            continue

        iocs.append({
            "type": "ip",
            "value": ip,
            "source": "IPsum",
            "severity": "HIGH",  # refinada pelo classifier a partir do abuse_score
            "description": f"IPsum — listado em {hits} blacklists públicas",
            "first_seen": today,
            "last_seen": today,
            "country": None,
            "abuse_score": _hits_to_score(hits),
            "mitre_technique_id": None,
            "mitre_tactic": None,
            "confidence_score": None,
        })

        if len(iocs) >= MAX_IPS:
            break

    print(f"[ipsum] {len(iocs)} IPs (>= {MIN_LISTS} blacklists) collected")
    return iocs
