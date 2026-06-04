import os
import json
import ipaddress
import requests
from datetime import date

from src.enrichers import geoip_db

# Spamhaus DROP (Don't Route Or Peer): netblocks (CIDR) sequestrados ou alugados
# por operações de spam/cibercrime — listados pela Spamhaus a partir de research
# próprio. Falso-positivo ~zero (não inclui espaço de rede legítimo) e é um sinal
# ÚNICO de INFRAESTRUTURA: ao resolver o ASN de cada netblock, ligamos esses ranges
# ao hub de ASN do grafo de correlação, evidenciando hosting bulletproof por ASN.
#
# Formato (JSON-lines): {"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
ENDPOINT = "https://www.spamhaus.org/drop/drop_v4.json"
HEADERS = {"User-Agent": "AEGIS-CTI/1.0 (+https://aegiscti.me)"}
MAX_NETBLOCKS = 5000
# Hijacked/bulletproof: alta confiança por design. Score alto e estável (não é
# por-IP como o DShield); refinado pelo classifier (netblock usa o abuse_score).
ABUSE_SCORE = 88


def _open_asn_reader():
    """Reader GeoLite2-ASN (env → glob), ou None. Nunca propaga exception."""
    env_path = os.getenv("MAXMIND_ASN_DB_PATH")
    path = env_path if (env_path and os.path.exists(env_path)) else geoip_db.find_mmdb("GeoLite2-ASN")
    if not path:
        return None
    try:
        import geoip2.database
        return geoip2.database.Reader(path)
    except Exception:
        return None


def collect() -> list[dict]:
    today = date.today().isoformat()
    try:
        response = requests.get(ENDPOINT, headers=HEADERS, timeout=30)
        response.raise_for_status()
        content = response.text
    except Exception as e:
        print(f"[spamhaus] Error fetching DROP feed: {e}")
        return []

    reader = _open_asn_reader()
    iocs = []
    try:
        for line in content.splitlines():
            line = line.strip()
            # Pula linhas de metadados/comentário (a lista traz um trailer não-CIDR).
            if not line or not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
            except (ValueError, TypeError):
                continue

            cidr = entry.get("cidr")
            if not cidr:
                continue

            # ASN do netblock — sinal de "mesma infraestrutura" que liga o range aos
            # IPs do mesmo ASN no grafo (get_correlation_graph: hub de ASN).
            asn = None
            if reader:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    asn = reader.asn(str(net.network_address)).autonomous_system_number
                except Exception:
                    asn = None

            iocs.append({
                "type": "netblock",
                "value": cidr,
                "source": "Spamhaus-DROP",
                "severity": "HIGH",  # refinada pelo classifier a partir do abuse_score
                "description": f"Spamhaus DROP — netblock hijacked/bulletproof "
                               f"({entry.get('sblid', '?')}, {entry.get('rir', '?')})",
                "first_seen": today,
                "last_seen": today,
                "country": None,
                "abuse_score": ABUSE_SCORE,
                "asn": asn,
                "mitre_technique_id": None,
                "mitre_tactic": None,
                "confidence_score": None,
            })

            if len(iocs) >= MAX_NETBLOCKS:
                break
    finally:
        if reader:
            reader.close()

    n_asn = sum(1 for i in iocs if i.get("asn") is not None)
    print(f"[spamhaus] {len(iocs)} netblocks DROP collected ({n_asn} com ASN)")
    return iocs
