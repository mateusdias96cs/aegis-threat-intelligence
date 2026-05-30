import os
from collections import defaultdict

# Points per severity source; capped at 100
_SEVERITY_WEIGHTS = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 5}


def _compute_abuse_score(severities: list[str]) -> int:
    return min(100, sum(_SEVERITY_WEIGHTS.get(s, 10) for s in severities))


def enrich_batch(new_iocs: list[dict], collected_iocs: list[dict]) -> list[dict]:
    """
    Enriquece IPs novos via cruzamento com IOCs já coletados + GeoIP2 local.

    new_iocs      — IOCs novos a enriquecer (modifica in-place).
    collected_iocs — todos os IOCs IP coletados nesta execução (base de cruzamento).
    """
    # index: ip -> [severity, ...] de todas as fontes que o reportaram
    ip_severity_index: dict[str, list[str]] = defaultdict(list)
    for ioc in collected_iocs:
        if ioc.get("type") == "ip" and ioc.get("value"):
            ip_severity_index[ioc["value"]].append(ioc.get("severity", "LOW"))

    ip_iocs = [ioc for ioc in new_iocs if ioc.get("type") == "ip" and ioc.get("value")]
    print(f"[ip_enricher] enriching {len(ip_iocs)} new IPs via cross-source + GeoIP2")

    # Open GeoIP2 reader once for all IPs
    reader = None
    db_path = os.getenv("MAXMIND_DB_PATH")
    if db_path:
        try:
            import geoip2.database
            reader = geoip2.database.Reader(db_path)
        except Exception as e:
            print(f"[ip_enricher] GeoIP2 reader failed to open: {e}")

    try:
        for ioc in ip_iocs:
            ip = ioc["value"].split(":")[0]

            matches = ip_severity_index.get(ip, [])
            if matches:
                ioc["abuse_score"] = _compute_abuse_score(matches)

            if ioc.get("country") is None and reader:
                try:
                    ioc["country"] = reader.country(ip).country.iso_code
                except Exception:
                    pass
    finally:
        if reader:
            reader.close()

    return new_iocs
