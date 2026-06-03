import os
from collections import defaultdict

from src.enrichers import geoip_db

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


def _open_geoip_reader(env_var: str, edition_id: str, label: str):
    """Abre um Reader GeoIP2 tolerante a filesystem efêmero (Render). None se indisponível.

    Resolve o .mmdb por: env var (se o arquivo REALMENTE existir) → glob em data/.
    No Render o arquivo apontado pelo `.env` some no restart; em vez de estourar
    FileNotFoundError, devolvemos None e o enrichment apenas não preenche country/asn.
    Nunca propaga exception — degradação silenciosa por design.
    """
    env_path = os.getenv(env_var)
    path = env_path if (env_path and os.path.exists(env_path)) else geoip_db.find_mmdb(edition_id)
    if not path:
        return None
    try:
        import geoip2.database
        return geoip2.database.Reader(path)
    except Exception as e:
        print(f"[ip_enricher] GeoIP2 {label} indisponível ({e}) — seguindo sem ele")
        return None


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

    # Open GeoIP2 readers once for all IPs (country + ASN; both optional).
    # Resolução robusta (env → glob) com fallback silencioso — ver _open_geoip_reader.
    reader = _open_geoip_reader("MAXMIND_DB_PATH", "GeoLite2-Country", "Country")
    asn_reader = _open_geoip_reader("MAXMIND_ASN_DB_PATH", "GeoLite2-ASN", "ASN")

    try:
        for ioc in ip_iocs:
            ip = ioc["value"].split(":")[0]

            matches = ip_severity_index.get(ip, [])
            if matches:
                computed = _compute_abuse_score(matches)
                # Não rebaixa um abuse_score REAL (ex.: volume de ataques do DShield):
                # a corroboração entre fontes só pode reforçar, nunca apagar evidência.
                existing = ioc.get("abuse_score")
                ioc["abuse_score"] = max(computed, existing) if existing is not None else computed

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
