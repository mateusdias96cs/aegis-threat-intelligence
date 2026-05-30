import os
from collections import defaultdict

# Score-base por severidade da fonte mais forte (alinhado aos limiares do
# classifier: >=90 CRITICAL, >=70 HIGH, >=40 MEDIUM). Preserva a severidade
# da fonte para IPs de fonte única em vez de rebaixá-los.
_SEVERITY_WEIGHTS = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 45, "LOW": 25}
# Bônus por fonte adicional que reporta o mesmo IP (corroboração).
_CORROBORATION_BONUS = 10

# Categorias de abuso sintéticas por fonte de IP (chave = source.lower()).
# IDs seguem o padrão AbuseIPDB que o Kill Chain do frontend já mapeia (ABUSE_TO_KC):
#   14 = Port Scan → Reconnaissance.
# Reacende a fase do Kill Chain de IP que dependia das categorias do AbuseIPDB.
_SOURCE_ABUSE_CATEGORIES: dict[str, dict[int, int]] = {
    "greynoise":       {14: 1},
    "emergingthreats": {14: 1},
}


def _compute_abuse_score(severities: list[str]) -> int:
    if not severities:
        return 0
    base = max(_SEVERITY_WEIGHTS.get(s, 40) for s in severities)
    bonus = _CORROBORATION_BONUS * (len(severities) - 1)
    return min(100, base + bonus)


def enrich_batch(new_iocs: list[dict], collected_iocs: list[dict]) -> list[dict]:
    """
    Enriquece IPs novos via cruzamento com IOCs já coletados + GeoIP2 local.

    new_iocs      — IOCs novos a enriquecer (modifica in-place).
    collected_iocs — todos os IOCs IP coletados nesta execução (base de cruzamento).
    """
    # index: ip (sem porta) -> [severity, ...] de todas as fontes que o reportaram
    ip_severity_index: dict[str, list[str]] = defaultdict(list)
    for ioc in collected_iocs:
        if ioc.get("type") == "ip" and ioc.get("value"):
            ip_key = ioc["value"].split(":")[0]
            ip_severity_index[ip_key].append(ioc.get("severity", "LOW"))

    ip_iocs = [ioc for ioc in new_iocs if ioc.get("type") == "ip" and ioc.get("value")]
    print(f"[ip_enricher] enriching {len(ip_iocs)} new IPs via cross-source + GeoIP2")

    # Open GeoIP2 readers once for all IPs (country + ASN; both optional)
    reader = None
    db_path = os.getenv("MAXMIND_DB_PATH")
    if db_path:
        try:
            import geoip2.database
            reader = geoip2.database.Reader(db_path)
        except Exception as e:
            print(f"[ip_enricher] GeoIP2 reader failed to open: {e}")

    asn_reader = None
    asn_db_path = os.getenv("MAXMIND_ASN_DB_PATH")
    if asn_db_path:
        try:
            import geoip2.database
            asn_reader = geoip2.database.Reader(asn_db_path)
        except Exception as e:
            print(f"[ip_enricher] GeoIP2 ASN reader failed to open: {e}")

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

            # ASN — sinal forte de "mesma infraestrutura" (ex.: bulletproof hosting).
            # Alimenta a correlação por ASN no get_campaign_context.
            if ioc.get("asn") is None and asn_reader:
                try:
                    ioc["asn"] = asn_reader.asn(ip).autonomous_system_number
                except Exception:
                    pass

            # Categorias sintéticas a partir da fonte — alimenta o Kill Chain de IP.
            if not ioc.get("abuse_categories"):
                cats = _SOURCE_ABUSE_CATEGORIES.get((ioc.get("source") or "").lower())
                if cats:
                    ioc["abuse_categories"] = dict(cats)
    finally:
        if reader:
            reader.close()
        if asn_reader:
            asn_reader.close()

    return new_iocs
