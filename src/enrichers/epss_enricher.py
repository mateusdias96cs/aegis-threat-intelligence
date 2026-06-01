"""
Enriquecimento de CVEs com EPSS (Exploit Prediction Scoring System, FIRST.org).

EPSS estima a PROBABILIDADE de um CVE ser explorado nos próximos 30 dias — sinal
preditivo que complementa o CISA-KEV (já explorado) e o CVSS (severidade se
explorado). É gratuito, sem API key, e a API aceita lote (várias CVEs por chamada).
"""

import requests

EPSS_API = "https://api.first.org/data/v1/epss"
CHUNK = 100      # limite padrão da API por requisição
TIMEOUT = 20


def fetch_epss(cve_ids: list[str]) -> dict[str, dict]:
    """Busca EPSS em lote. Retorna {CVE: {"epss": float, "percentile": float}}."""
    ids = [c for c in dict.fromkeys(cve_ids) if c]  # dedup preservando ordem
    out: dict[str, dict] = {}
    for i in range(0, len(ids), CHUNK):
        chunk = ids[i:i + CHUNK]
        try:
            resp = requests.get(EPSS_API, params={"cve": ",".join(chunk)}, timeout=TIMEOUT)
            resp.raise_for_status()
            for row in resp.json().get("data", []):
                cve = row.get("cve")
                if not cve:
                    continue
                try:
                    out[cve] = {
                        "epss":       float(row["epss"]),
                        "percentile": float(row["percentile"]),
                    }
                except (KeyError, TypeError, ValueError):
                    continue
        except Exception as e:
            print(f"[epss] lote {i // CHUNK} falhou: {e}")
    return out


def enrich_batch(iocs: list[dict]) -> list[dict]:
    """Enriquece os IOCs do tipo cve com epss_score + epss_percentile (in-place)."""
    cve_iocs = [i for i in iocs if i.get("type") == "cve" and i.get("value")]
    if not cve_iocs:
        return iocs

    scores = fetch_epss([i["value"] for i in cve_iocs])
    hit = 0
    for ioc in cve_iocs:
        data = scores.get(ioc["value"])
        if data:
            ioc["epss_score"]      = data["epss"]
            ioc["epss_percentile"] = data["percentile"]
            hit += 1
    print(f"[epss] {hit}/{len(cve_iocs)} CVEs enriquecidos com EPSS")
    return iocs
