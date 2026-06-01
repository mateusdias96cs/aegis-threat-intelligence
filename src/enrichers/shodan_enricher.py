"""
Enriquecimento de IPs com Shodan InternetDB (https://internetdb.shodan.io).

InternetDB é o feed gratuito e SEM API key da Shodan: para um IP, devolve portas
abertas, CPEs, hostnames, tags (ex.: "scanner", "compromised", "c2") e a lista de
CVEs a que o host está exposto. É enriquecimento de CONTEXTO — não altera o score
(mantém o sistema estável); só dá ao analista a superfície real do atacante.

Não redundante com a live-enrichment do drawer (que usa AbuseIPDB).
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

INTERNETDB = "https://internetdb.shodan.io/{ip}"
TIMEOUT = 6
WORKERS = 10
MAX_IPS = 600   # teto de segurança por execução (evita varredura excessiva)


def _lookup(ip: str):
    """Consulta um IP no InternetDB. Retorna (ip, dict|None). 404 = sem dados."""
    try:
        resp = requests.get(INTERNETDB.format(ip=ip), timeout=TIMEOUT)
        if resp.status_code == 404:
            return ip, None
        resp.raise_for_status()
        d = resp.json()
        data = {
            "ports":     d.get("ports") or [],
            "tags":      d.get("tags") or [],
            "vulns":     d.get("vulns") or [],
            "hostnames": d.get("hostnames") or [],
        }
        return ip, (data if any(data.values()) else None)
    except Exception:
        return ip, None


def enrich_batch(iocs: list[dict]) -> list[dict]:
    """Enriquece os IOCs do tipo ip com `shodan_data` (in-place)."""
    ip_iocs = [i for i in iocs if i.get("type") == "ip" and i.get("value")]
    if not ip_iocs:
        return iocs

    # Agrupa por IP (sem porta) para não consultar o mesmo host duas vezes.
    ip_map: dict[str, list[dict]] = {}
    for ioc in ip_iocs:
        ip = ioc["value"].split(":")[0]
        ip_map.setdefault(ip, []).append(ioc)

    ips = list(ip_map)[:MAX_IPS]
    print(f"[shodan] consultando InternetDB para {len(ips)} IPs (sem key)")

    hit = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = [ex.submit(_lookup, ip) for ip in ips]
        for fut in as_completed(futures):
            ip, data = fut.result()
            if data:
                for ioc in ip_map[ip]:
                    ioc["shodan_data"] = data   # dict; insert_many serializa em JSON
                hit += 1

    print(f"[shodan] {hit}/{len(ips)} IPs com dados InternetDB (portas/tags/vulns)")
    return iocs
