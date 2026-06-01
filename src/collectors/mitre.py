import json
import requests
from src.storage import mitre_cache

FEED_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

KEYWORD_TO_TECHNIQUE = {
    "brute":       "T1110",
    "ssh":         "T1110",
    "password":    "T1110",
    "phishing":    "T1566",
    "phish":       "T1566",
    "sql":         "T1190",
    "sqli":        "T1190",
    "xss":         "T1190",
    "cross-site":  "T1190",
    "ransomware":  "T1486",
    "c2":          "T1071",
    "command":     "T1071",
    "control":     "T1071",
    "botnet":      "T1071",
    "scan":        "T1046",
    "recon":       "T1046",
    "enumerat":    "T1046",
    "exploit":     "T1190",
    "cve":         "T1190",
    "rce":         "T1190",
    "credential":  "T1078",
    "login":       "T1078",
    "auth":        "T1078",
    "backdoor":    "T1059",
    "rat":         "T1059",
    "trojan":      "T1059",
}

# Fallback determinístico por fonte (chave = source.lower()).
# Feeds de IP trazem descrição genérica e não casam nenhum keyword acima, mas a
# própria fonte já indica a TTP do indicador. Usado só quando o texto não casa.
SOURCE_TO_TECHNIQUE = {
    "greynoise":       "T1595",  # Active Scanning — scanners observados na internet
    "emergingthreats": "T1595",  # Active Scanning — hosts hostis conhecidos
    "dshield":         "T1595",  # Active Scanning — atacantes observados por sensores ISC
    "feodotracker":    "T1071",  # Application Layer Protocol — C2 de botnet
    "feodo-tracker":   "T1071",
}


def load_techniques() -> dict:
    # Tenta cache do banco primeiro (TTL 30 dias)
    cached = mitre_cache.load()
    if cached:
        return cached

    # Cache ausente ou expirado — busca do GitHub
    print("[mitre] buscando técnicas do GitHub MITRE CTI...")
    try:
        response = requests.get(FEED_URL, timeout=60)
        response.raise_for_status()
        objects = response.json().get("objects", [])
    except requests.RequestException as e:
        print(f"[mitre] falha ao buscar ATT&CK data: {e}")
        # Tenta retornar cache expirado como fallback de emergência
        try:
            from sqlalchemy import text
            from src.storage.database import engine
            with engine.connect() as conn:
                row = conn.execute(
                    text("SELECT value FROM kv_cache WHERE key = 'mitre_techniques'")
                ).fetchone()
            if row:
                data = json.loads(row[0])
                print(f"[mitre] usando cache expirado como fallback ({len(data)} técnicas)")
                return data
        except Exception:
            pass
        return {}

    techniques = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated"):
            continue

        tech_id = None
        tech_url = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id")
                tech_url = ref.get("url")
                break

        if not tech_id:
            continue

        tactic = None
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactic = phase["phase_name"].replace("-", " ").title()
                break

        techniques[tech_id] = {
            "id": tech_id,
            "name": obj.get("name"),
            "tactic": tactic,
            "url": tech_url,
        }

    if techniques:
        mitre_cache.save(techniques)

    return techniques


def _resolve(tech_id: str, techniques: dict) -> dict | None:
    """Resolve uma técnica; cai para a técnica-pai se a sub-técnica não existir
    no índice (ex.: T1003.002 → T1003)."""
    t = techniques.get(tech_id)
    if t:
        return t
    if "." in tech_id:
        return techniques.get(tech_id.split(".")[0])
    return None


def map_ioc_to_technique(ioc: dict, techniques: dict) -> dict | None:
    # 1) Técnicas ATT&CK REAIS atribuídas pela fonte (OTX attack_ids) — prioridade
    #    máxima. É atribuição feita por um analista, não inferência por substring.
    attack_ids = ioc.get("attack_ids") or []
    if attack_ids:
        resolved: list[dict] = []
        for tid in attack_ids:
            t = _resolve(tid, techniques)
            if t and t not in resolved:
                resolved.append(t)
        if resolved:
            # Persiste a Kill Chain completa (todas as técnicas da campanha).
            ioc["mitre_techniques"] = [
                {"id": t["id"], "name": t["name"], "tactic": t["tactic"]}
                for t in resolved
            ]
            # Técnica primária = a primeira com tática conhecida (para o card resumo).
            for t in resolved:
                if t.get("tactic"):
                    return t
            return resolved[0]

    # 2) Keyword matching em texto livre — fallback para fontes sem attack_ids.
    haystack = " ".join(filter(None, [
        ioc.get("description", "") or "",
        ioc.get("value", "") or "",
    ])).lower()

    for keyword, tech_id in KEYWORD_TO_TECHNIQUE.items():
        if keyword in haystack:
            return techniques.get(tech_id)

    # 3) Fallback: nenhum keyword casou — usa a TTP característica da fonte.
    source_key = (ioc.get("source") or "").lower()
    tech_id = SOURCE_TO_TECHNIQUE.get(source_key)
    if tech_id:
        return techniques.get(tech_id)

    return None
