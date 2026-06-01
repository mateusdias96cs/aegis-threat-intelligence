import json
from datetime import datetime

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# ── Source reliability data ───────────────────────────────────────────────────
# Keys are lowercase normalized source names.

_SOURCE_DATA: dict[str, dict] = {
    "cisa-kev": {
        "score": 100,
        "referencia": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "justificativa": "Catálogo oficial CISA de vulnerabilidades exploradas ativamente",
    },
    "feodo-tracker": {
        "score": 85,
        "referencia": "https://feodotracker.abuse.ch",
        "justificativa": "Tracker especializado em C2 de botnets financeiros (Emotet, Dridex, etc.)",
    },
    "threatfox": {
        "score": 80,
        "referencia": "https://threatfox.abuse.ch",
        "justificativa": "Plataforma crowdsourced de IOCs verificados pela abuse.ch",
    },
    "dshield": {
        "score": 78,
        "referencia": "https://isc.sans.edu/ipinfo.html?ip={value}",
        "justificativa": "Telemetria de ataque do SANS ISC — milhares de sensores de firewall globais",
    },
    "abuseipdb-blacklist": {
        "score": 75,
        "referencia": "https://www.abuseipdb.com/check/{value}",
        "justificativa": "Lista negra de IPs com histórico confirmado de ataques",
    },
    "urlhaus": {
        "score": 70,
        "referencia": "https://urlhaus.abuse.ch",
        "justificativa": "Tracker de URLs maliciosas com verificação ativa",
    },
    "alienvault-otx": {
        "score": 55,
        "referencia": "https://otx.alienvault.com",
        "justificativa": "Feed colaborativo de ameaças de amplo espectro",
    },
}

# "FeodoTracker".lower() == "feodotracker" — maps to canonical "feodo-tracker"
_SOURCE_ALIASES: dict[str, str] = {
    "feodotracker": "feodo-tracker",
}

# ── Famílias de telemetria INDEPENDENTE ───────────────────────────────────────
# Corroboração só é forte quando vem de fontes independentes. Vários feeds da MESMA
# organização/telemetria (ex.: ThreatFox + URLhaus + Feodo são todos abuse.ch) NÃO
# são confirmações independentes — somá-los infla a confiança com redundância.
# A corroboração (C) passa a contar FAMÍLIAS distintas, não nomes de feed.
_SOURCE_FAMILY: dict[str, str] = {
    # abuse.ch — mesma organização, telemetria sobreposta
    "threatfox":           "abuse.ch",
    "urlhaus":             "abuse.ch",
    "feodo-tracker":       "abuse.ch",
    # telemetria honeypot / firewall (sensores de borda)
    "dshield":             "honeypot",
    "greynoise":           "honeypot",
    "emergingthreats":     "honeypot",
    # catálogo autoritativo
    "cisa-kev":            "autoritativa",
    # reputação de IP
    "abuseipdb-blacklist": "reputacao",
    # comunidade / feed colaborativo
    "alienvault-otx":      "comunidade",
}


def _independent_families(sources) -> list[str]:
    """Reduz um conjunto de nomes de feed às FAMÍLIAS independentes que representam.
    Feeds sem família mapeada contam como família própria (são independentes)."""
    fams: set[str] = set()
    for s in sources:
        key = _resolve_source(s)
        if not key:
            continue
        fams.add(_SOURCE_FAMILY.get(key, key))
    return sorted(fams)

# Type-specific reference URL templates
_TYPE_REFS: dict[str, str] = {
    "cve":    "https://nvd.nist.gov/vuln/detail/{value}",
    "ip":     "https://www.abuseipdb.com/check/{value}",
    "hash":   "https://www.virustotal.com/gui/file/{value}",
    "domain": "https://www.virustotal.com/gui/domain/{value}",
    "url":    "{value}",
}


def _resolve_source(source: str) -> str:
    """Normalizes a raw source name to the canonical lowercase key."""
    key = (source or "").lower()
    return _SOURCE_ALIASES.get(key, key)


def _get_source_info(source: str, value: str) -> tuple[int, str, str]:
    """Returns (S_score, referencia, justificativa) for a source name."""
    key = _resolve_source(source)
    data = _SOURCE_DATA.get(key, {})
    score = data.get("score", 50)
    ref = data.get("referencia", "").replace("{value}", value)
    justification = data.get("justificativa", "Fonte não categorizada")
    return score, ref, justification


def _get_interpretation(score: float) -> str:
    if score >= 85:
        return "ALTA confiança — múltiplas fontes confirmadas, ação recomendada"
    if score >= 70:
        return "CONFIANÇA MODERADA-ALTA — fonte confiável, verificar contexto"
    if score >= 55:
        return "CONFIANÇA MODERADA — investigar antes de agir"
    if score >= 40:
        return "BAIXA confiança — fonte variável, priorizar corroboração"
    return "MUITO BAIXA confiança — usar apenas como referência"


def calculate_score_breakdown(ioc: dict, source_count: int = 1, sources=None) -> dict:
    """
    Score = (S × 0.40) + (C × 0.30) + (T × 0.30)

    S = Source Reliability, C = Corroboration (sightings), T = Type Severity.

    `sources` (conjunto de nomes de feed que reportaram o IOC) é a entrada
    preferida: C é derivado das FAMÍLIAS independentes, não da contagem bruta de
    feeds — feeds redundantes da mesma organização não inflam a confiança.
    `source_count` é mantido como fallback para chamadas legadas sem `sources`.
    Returns a full audit dict (score_breakdown).
    """
    source   = ioc.get("source", "")
    value    = ioc.get("value", "")
    ioc_type = (ioc.get("type") or "").lower()

    # Conjunto de fontes que confirmaram o IOC (inclui a âncora). Base tanto do S
    # (confiabilidade da fonte mais confiável) quanto do C (famílias independentes).
    if sources is None:
        all_sources = {source} if source else set()
        feed_count  = source_count
    else:
        all_sources = {s for s in set(sources) | ({source} if source else set()) if s}
        feed_count  = len(all_sources)

    # S — Source Reliability. Com múltiplas fontes, a confiabilidade do IOC é a da
    # fonte MAIS confiável que o reportou — não a âncora (a primeira a ver o IOC).
    # Sem isto, um IOC confirmado pela CISA (S=100) mas visto antes pelo OTX (S=55)
    # ficaria preso em S=55: o score passaria a depender da ordem de ingestão.
    best_source, best_S = source, (_get_source_info(source, value)[0] if source else 0)
    for s in all_sources:
        s_score = _get_source_info(s, value)[0]
        if s_score > best_S:
            best_S, best_source = s_score, s
    S, source_ref, source_justification = _get_source_info(best_source, value)

    # C — Corroboração por FAMÍLIAS de fonte independente (STIX 2.1 Sightings).
    families = _independent_families(all_sources) or ["desconhecida"]
    if sources is None:
        # Sem a lista de feeds, respeita a contagem legada como nº de famílias.
        fam_count = max(source_count, len(families), 1)
    else:
        fam_count = len(families)

    if fam_count >= 3:
        C = 100
        corroboration_justification = f"IOC confirmado por {fam_count} famílias de fontes independentes"
    elif fam_count == 2:
        C = 66
        corroboration_justification = "IOC confirmado por 2 famílias de fontes independentes"
    else:
        C = 33
        corroboration_justification = f"IOC observado em 1 família de fonte ({families[0]})"

    # Transparência sobre redundância: mais feeds que famílias = feeds da mesma
    # organização que NÃO somam corroboração independente.
    if feed_count > fam_count:
        corroboration_justification += (
            f" — {feed_count} feeds, mas {fam_count} família(s) independente(s) "
            f"(feeds redundantes não elevam o C)"
        )

    # T — Type Severity
    cvss  = ioc.get("cvss_score")
    abuse = ioc.get("abuse_score")
    epss_score = ioc.get("epss_score")
    epss_pct   = ioc.get("epss_percentile")

    if ioc_type == "cve":
        if cvss is not None:
            T         = min(100.0, float(cvss) * 10)
            type_base = f"CVSS {float(cvss):.1f}/10 (NVD)"
        elif epss_pct is not None:
            # Sem CVSS: o percentil EPSS (probabilidade de exploração) é um sinal
            # real e discrimina melhor que o padrão fixo 80.
            T         = max(60.0, round(float(epss_pct) * 100, 1))
            type_base = f"EPSS percentil {float(epss_pct) * 100:.1f}% (CVSS indisponível)"
        else:
            T         = 80.0
            type_base = "padrão CVE (CVSS/EPSS indisponíveis)"
        type_ref = _TYPE_REFS["cve"].replace("{value}", value)

    elif ioc_type == "ip":
        if abuse is not None:
            T        = float(abuse)
            type_base = f"AbuseIPDB score {abuse}"
        else:
            T        = 60.0
            type_base = "padrão IP (sem score AbuseIPDB)"
        type_ref = _TYPE_REFS["ip"].replace("{value}", value)

    elif ioc_type == "hash":
        T, type_base = 75.0, "padrão hash"
        type_ref = _TYPE_REFS["hash"].replace("{value}", value)

    elif ioc_type == "url":
        T, type_base = 65.0, "padrão URL"
        type_ref = _TYPE_REFS["url"].replace("{value}", value)

    elif ioc_type == "domain":
        T, type_base = 60.0, "padrão domain"
        type_ref = _TYPE_REFS["domain"].replace("{value}", value)

    else:
        T, type_base, type_ref = 50.0, "padrão", ""

    score_final   = (S * 0.40) + (C * 0.30) + (T * 0.30)
    score_rounded = round(score_final)

    return {
        "formula": "Score = (S × 0.40) + (C × 0.30) + (T × 0.30)",
        "source_reliability": {
            "fonte":        best_source,
            "score":        S,
            "peso":         0.40,
            "contribuicao": round(S * 0.40, 2),
            "referencia":   source_ref,
            "justificativa": source_justification,
        },
        "corroboration": {
            "fontes_count":  feed_count,
            "familias":      families,
            "familias_count": fam_count,
            "score":         C,
            "peso":          0.30,
            "contribuicao":  round(C * 0.30, 2),
            "justificativa": corroboration_justification,
        },
        "type_severity": {
            "tipo":         ioc_type or "unknown",
            "score":        round(T, 2),
            "peso":         0.30,
            "contribuicao": round(T * 0.30, 2),
            "base":         type_base,
            "referencia":   type_ref,
            # Probabilidade de exploração (EPSS) — exposta para priorização do analista,
            # independente de entrar no T. None quando não é CVE ou não foi enriquecido.
            "epss":            epss_score,
            "epss_percentile": epss_pct,
        },
        "score_final":      round(score_final, 2),
        "score_arredondado": score_rounded,
        "interpretacao":    _get_interpretation(score_final),
        "aviso":            "Score é indicador de confiança, não certeza absoluta.",
    }


def apply_confidence(iocs: list, value_sources: dict[str, set] | None = None) -> list:
    """Applies the new 3-component scoring formula to each IOC in the batch.

    `value_sources` (value -> set of distinct sources observed for that value)
    carries cross-source corroboration captured BEFORE deduplication. Without it,
    the deduplicator would have already collapsed multi-source sightings into a
    single record and the corroboration count (C) would always be 1.
    """
    today = datetime.utcnow().strftime("%Y-%m-%d")

    # Fallback: count sightings within this batch only (pre-corroboration behaviour)
    value_counts: dict[str, int] = {}
    if value_sources is None:
        for ioc in iocs:
            val = ioc.get("value", "")
            value_counts[val] = value_counts.get(val, 0) + 1

    for ioc in iocs:
        val = ioc.get("value", "")

        if value_sources is not None:
            sources      = {s for s in (value_sources.get(val) or {ioc.get("source", "")}) if s}
            source_count = max(1, len(sources))
        else:
            sources      = {ioc.get("source", "")}
            source_count = value_counts.get(val, 1)

        breakdown = calculate_score_breakdown(ioc, source_count, sources=sources)
        score     = breakdown["score_arredondado"]

        ioc["confidence_score"]   = score
        ioc["score_original"]     = float(score)
        ioc["score_atual"]        = float(score)
        ioc["score_breakdown"]    = json.dumps(breakdown, ensure_ascii=False)
        ioc["ioc_status"]         = "ACTIVE"
        ioc["reactivation_count"] = 0
        # Persiste as fontes corroborantes (apenas quando há mais de uma) — alimenta
        # o painel de contexto e mantém o C do score consistente após decay/recalc.
        if len(sources) > 1:
            ioc["correlated_sources"] = json.dumps(sorted(sources), ensure_ascii=False)
        if not ioc.get("last_seen"):
            ioc["last_seen"] = today

    return iocs


def classify(iocs: list) -> list:
    for ioc in iocs:
        score = ioc.get("abuse_score")

        if score is not None:
            if score >= 90:
                ioc["severity"] = "CRITICAL"
            elif score >= 70:
                ioc["severity"] = "HIGH"
            elif score >= 40:
                ioc["severity"] = "MEDIUM"
            elif score > 0:
                ioc["severity"] = "LOW"
            else:
                ioc["severity"] = ioc.get("severity") or "MEDIUM"
        elif ioc.get("source") == "CISA-KEV":
            pass
        else:
            ioc["severity"] = ioc.get("severity") or "MEDIUM"

    return iocs
