import os
import time
import requests
from datetime import date

BASE_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# O OTX é lento e instável sob carga: um único GET de 30s estourava o read timeout
# e derrubava a coleta inteira ("[otx] failed to fetch pulses: Read timed out").
# Damos mais fôlego (60s) e 3 tentativas com backoff crescente (10s/20s/30s) para
# absorver instabilidade transitória sem travar o pipeline.
_TIMEOUT = 60
_BACKOFFS = [10, 20, 30]  # espera após a 1ª/2ª/3ª falha (a 3ª não dorme: é a última)


def _get_with_retry(url: str, headers: dict) -> dict | None:
    """GET no OTX com timeout de 60s e backoff exponencial. None se todas falharem.

    Esgotadas as 3 tentativas, devolve None e o chamador preserva o que já coletou
    (dados parciais) — o pipeline nunca trava por causa do OTX.
    """
    for attempt, wait in enumerate(_BACKOFFS, start=1):
        try:
            response = requests.get(url, headers=headers, timeout=_TIMEOUT)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            if attempt < len(_BACKOFFS):
                print(f"[otx] tentativa {attempt}/{len(_BACKOFFS)} falhou: {e} — "
                      f"nova tentativa em {wait}s")
                time.sleep(wait)
            else:
                print(f"[otx] todas as {len(_BACKOFFS)} tentativas falharam: {e}")
    return None

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
        data = _get_with_retry(url, headers)
        if data is None:
            # Falha após todas as tentativas: NÃO descarta o que já veio das páginas
            # anteriores — compatível com o fallback de dados parciais existente.
            if iocs:
                print(f"[otx] retornando {len(iocs)} indicadores parciais coletados antes da falha")
            else:
                print("[otx] nenhum dado obtido — retornando lista vazia")
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
