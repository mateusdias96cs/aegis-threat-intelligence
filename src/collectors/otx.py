import os
import requests
from datetime import date

BASE_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

TYPE_MAP = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "FileHash-MD5": "hash",
    "FileHash-SHA1": "hash",
    "FileHash-SHA256": "hash",
    "URL": "url",
    "CVE": "cve",
}


def _pulse_meta(pulse: dict) -> dict:
    """Extrai os metadados estruturados de um pulse OTX.

    Um pulse JÁ É uma campanha real reportada por um analista: traz o ator
    (`adversary`), as técnicas ATT&CK atribuídas (`attack_ids`) e a família de
    malware. Esses sinais valem muito mais que o keyword-matching do mapeador —
    são atribuição humana, não inferência por substring.
    """
    adversary = (pulse.get("adversary") or "").strip()
    malware   = [m for m in (pulse.get("malware_families") or []) if m]
    # attack_ids vem como lista de strings ("T1190") ou de dicts {"id": "T1190"}.
    raw_attack = pulse.get("attack_ids") or []
    attack_ids = []
    for a in raw_attack:
        tid = a.get("id") if isinstance(a, dict) else a
        if tid:
            attack_ids.append(str(tid).upper())

    # Descrição enriquecida com atribuição — vira contexto acionável no drawer.
    parts = [pulse.get("name") or ""]
    if adversary:
        parts.append(f"Ator: {adversary}")
    if malware:
        parts.append(f"Malware: {', '.join(malware[:3])}")
    description = " | ".join(p for p in parts if p)

    return {
        "campaign_id":      pulse.get("id"),
        "adversary":        adversary or None,
        "attack_ids":       attack_ids,
        "description":      description,
        "created":          (pulse.get("created") or "")[:10] or None,
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
    pages_fetched = 0
    MAX_PAGES = 3

    while url and pages_fetched < MAX_PAGES:
        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as e:
            print(f"[otx] failed to fetch pulses: {e}")
            break

        for pulse in data.get("results", []):
            meta = _pulse_meta(pulse)

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
                    "description": meta["description"],
                    "first_seen": meta["created"],
                    "last_seen": today,
                    "severity": "HIGH",
                    "country": None,
                    "abuse_score": None,
                    # ── sinais estruturados da campanha ──────────────────────
                    "campaign_id":  meta["campaign_id"],
                    "adversary":    meta["adversary"],
                    "attack_ids":   meta["attack_ids"],
                })

        url = data.get("next")
        pages_fetched += 1

    return iocs
