import json
from datetime import datetime

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Fator de penalidade quando o IOC casa uma warninglist de infra legítima (P2).
# 0.5 = score rebaixado pela metade: forte sinal de provável FP sem zerar (o IOC
# continua visível para o analista, que pode contestar). Confirmado-FP manual
# (mark_false_positive) é mais agressivo (−80%).
_FP_WARNING_FACTOR = 0.5

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
    "ipsum": {
        "score": 72,
        "referencia": "https://github.com/stamparm/ipsum",
        "justificativa": "Agregador de 30+ blacklists públicas; nível 3 (>=3 listas) = baixo falso-positivo",
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
    # IPsum agrega blacklists honeypot/blocklist — mesma família para NÃO inflar a
    # corroboração quando concorda com DShield/ET (o consenso vira força no T, via
    # abuse_score por hit-count, não uma família extra no C).
    "ipsum":               "honeypot",
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


# ── Admiralty Code / NATO 6×6 (P4) ────────────────────────────────────────────
# Padrão NATO (recomendado pela SANS p/ CTI): avalia DOIS eixos SEPARADOS —
# confiabilidade da FONTE (letra A–F) e credibilidade da INFORMAÇÃO (número 1–6),
# sem um enviesar o outro. Mapeia direto no S (fonte) e C (corroboração) do AEGIS
# e dá ao analista a notação padrão de SOC ("B2"). Ver [[research-data-engineering]].
_ADM_LETTER_LABEL = {
    "A": "Confiável", "B": "Geralmente confiável", "C": "Razoavelmente confiável",
    "D": "Pouco confiável", "E": "Não confiável", "F": "Sem histórico",
}
_ADM_NUMBER_LABEL = {
    1: "Confirmado", 2: "Provavelmente verdadeiro", 3: "Possivelmente verdadeiro",
    4: "Duvidoso", 5: "Improvável", 6: "Não avaliável",
}

# Dimensões de enriquecimento que dão credibilidade extra a um IOC de fonte única.
_ENRICH_FIELDS = ("cvss_score", "abuse_score", "epss_score", "epss_percentile",
                  "shodan_data", "malware_context", "mitre_technique_id", "campaign_id",
                  "rdap_data")


def _admiralty_source_letter(best_source: str, S: float) -> str:
    """Confiabilidade da FONTE (A–F). Fonte sem histórico no catálogo = F (NATO:
    'fonte sem histórico suficiente'). Caso contrário, derivada do S."""
    if not best_source or _resolve_source(best_source) not in _SOURCE_DATA:
        return "F"
    if S >= 95:  return "A"
    if S >= 70:  return "B"
    if S >= 55:  return "C"
    if S >= 40:  return "D"
    return "E"


def _admiralty_info_number(fam_count: int, has_source: bool, enriched: bool, has_fp: bool) -> int:
    """Credibilidade da INFORMAÇÃO (1–6). Dirigida pela corroboração independente;
    rebaixada por warninglist (provável FP) e elevada por enriquecimento."""
    if not has_source:      return 6   # não avaliável
    if has_fp:              return 5   # improvável (casou infra legítima)
    if fam_count >= 3:      return 1   # confirmado por múltiplas fontes independentes
    if fam_count == 2:      return 2   # corroborado por 2 famílias
    return 3 if enriched else 4        # 1 fonte: enriquecida → possível; senão duvidoso


def _admiralty_grade(best_source: str, S: float, fam_count: int, ioc: dict, has_fp: bool) -> dict:
    has_source = bool(best_source)
    enriched   = any(ioc.get(f) is not None and ioc.get(f) != "" for f in _ENRICH_FIELDS)
    letter = _admiralty_source_letter(best_source, S)
    number = _admiralty_info_number(fam_count, has_source, enriched, has_fp)
    return {
        "grade":         f"{letter}{number}",
        "source_letter": letter,
        "source_label":  _ADM_LETTER_LABEL[letter],
        "info_number":   number,
        "info_label":    _ADM_NUMBER_LABEL[number],
        "explicacao": (
            f"Admiralty {letter}{number}: fonte {_ADM_LETTER_LABEL[letter].lower()} "
            f"({best_source or 'desconhecida'}); informação {_ADM_NUMBER_LABEL[number].lower()}. "
            "Eixos avaliados separadamente (padrão NATO/SANS)."
        ),
    }


def admiralty_for(breakdown: dict, row: dict | None = None) -> dict | None:
    """Deriva o grade Admiralty de um score_breakdown JÁ calculado (sem recomputar
    o score). Usado no serve-time para IOCs legados/decaídos cujo breakdown foi
    gravado antes do P4. `row` (linha do banco) é opcional, só p/ detectar
    enriquecimento quando a corroboração é de fonte única."""
    if not isinstance(breakdown, dict):
        return None
    sr = breakdown.get("source_reliability") or {}
    corr = breakdown.get("corroboration") or {}
    best_source = sr.get("fonte") or ""
    S = sr.get("score") or 0
    fam_count = corr.get("familias_count") or corr.get("fontes_count") or 1
    has_fp = "fp_warning" in breakdown or bool((row or {}).get("fp_warning"))
    return _admiralty_grade(best_source, S, fam_count, row or {}, has_fp)


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


# ── Completude de Contexto (D3) ───────────────────────────────────────────────
# Quantifica QUANTAS dimensões de contexto um IOC tem preenchidas, relativo ao
# que é alcançável para o seu TIPO (uma hash não tem geo; um CVE não tem ASN).
# Materializa o diferencial do AEGIS — "IOC bruto" vs. "IOC refinado" vira métrica.
_CONTEXT_DIMS: dict[str, list[str]] = {
    "ip":     ["geo", "network", "reputation", "surface", "ttp", "attribution", "corroboration"],
    "domain": ["registration", "geo", "ttp", "attribution", "corroboration"],
    "url":    ["registration", "geo", "ttp", "attribution", "corroboration"],
    "hash":   ["malware", "ttp", "attribution", "corroboration"],
    "cve":    ["severity", "exploitability", "ttp", "attribution", "corroboration"],
}

_DIM_LABEL: dict[str, str] = {
    "registration":   "Registro (RDAP)",
    "geo":            "Geolocalização",
    "network":        "ASN / Rede",
    "reputation":     "Reputação (AbuseIPDB)",
    "surface":        "Superfície (Shodan)",
    "malware":        "Família de Malware",
    "severity":       "Severidade (CVSS)",
    "exploitability": "Exploração (EPSS)",
    "ttp":            "Tática MITRE",
    "attribution":    "Atribuição (campanha/ator)",
    "corroboration":  "Corroboração multi-fonte",
}


def _dim_present(dim: str, ioc: dict) -> bool:
    if dim == "registration":   return bool(ioc.get("rdap_data"))
    if dim == "geo":            return bool(ioc.get("country"))
    if dim == "network":        return ioc.get("asn") is not None
    if dim == "reputation":     return ioc.get("abuse_score") is not None
    if dim == "surface":        return bool(ioc.get("shodan_data"))
    if dim == "malware":        return bool(ioc.get("malware_context"))
    if dim == "severity":       return ioc.get("cvss_score") is not None
    if dim == "exploitability": return ioc.get("epss_score") is not None or ioc.get("epss_percentile") is not None
    if dim == "ttp":            return bool(ioc.get("mitre_tactic") or ioc.get("mitre_technique_id"))
    if dim == "attribution":    return bool(ioc.get("campaign_id") or ioc.get("adversary"))
    if dim == "corroboration":  return bool(ioc.get("correlated_sources"))
    return False


def compute_context_completeness(ioc: dict) -> dict:
    """Mede a completude de contexto de um IOC (0–100) sobre as dimensões
    aplicáveis ao seu tipo. Funciona tanto com o dict do pipeline quanto com uma
    linha do banco (mesmas chaves)."""
    ioc_type = (ioc.get("type") or "").lower()
    dims = _CONTEXT_DIMS.get(ioc_type, ["ttp", "attribution", "corroboration"])
    detail = []
    filled = 0
    for d in dims:
        present = _dim_present(d, ioc)
        if present:
            filled += 1
        detail.append({"key": d, "label": _DIM_LABEL.get(d, d), "present": present})
    total = len(dims)
    score = round(filled / total * 100) if total else 0
    return {"score": score, "filled": filled, "total": total, "dimensions": detail}


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

    elif ioc_type in ("url", "domain"):
        # Padrão: url=65, domain=60. Com RDAP, discrimina pela idade do registro:
        # domínio < 30 dias = infraestrutura descartável (T sobe para 85);
        # 30–180 dias = suspeito (T sobe para 75); > 180 dias = padrão.
        base_T    = 65.0 if ioc_type == "url" else 60.0
        rdap      = ioc.get("rdap_data") if isinstance(ioc.get("rdap_data"), dict) else None
        age_days  = rdap.get("age_days") if rdap else None
        if age_days is not None and age_days >= 0:
            if age_days < 30:
                T         = 85.0
                type_base = f"RDAP: domínio com {age_days}d de existência (< 30d — alta suspeita)"
            elif age_days < 180:
                T         = 75.0
                type_base = f"RDAP: domínio com {age_days}d de existência (30–180d — suspeito)"
            else:
                T         = base_T
                type_base = f"RDAP: domínio com {age_days}d de existência (padrão {ioc_type})"
        else:
            T         = base_T
            type_base = f"padrão {ioc_type}"
        type_ref = _TYPE_REFS.get(ioc_type, _TYPE_REFS["url"]).replace("{value}", value)

    else:
        T, type_base, type_ref = 50.0, "padrão", ""

    score_base    = (S * 0.40) + (C * 0.30) + (T * 0.30)

    # Penalidade de warninglist (P2): o IOC casou uma lista de infra LEGÍTIMA
    # conhecida (cloud/CDN/DNS/Tranco). Não é deletado — mas é provável FP, então
    # o score é rebaixado por um fator. Mantém o IOC visível e auditável (o analista
    # vê qual lista casou) sem inflar a fila com infraestrutura benigna.
    fp_warning   = ioc.get("fp_warning")
    fp_block     = None
    if fp_warning:
        score_final = round(score_base * _FP_WARNING_FACTOR, 2)
        fp_block = {
            "lista":         fp_warning,
            "fator":         _FP_WARNING_FACTOR,
            "score_sem_penalidade": round(score_base, 2),
            "justificativa": (
                f"Casou lista de infraestrutura legítima conhecida ({fp_warning}) — "
                f"provável falso-positivo; score reduzido em "
                f"{round((1 - _FP_WARNING_FACTOR) * 100)}%."
            ),
        }
    else:
        score_final = round(score_base, 2)
    score_rounded = round(score_final)

    breakdown = {
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
        "score_final":      score_final,
        "score_arredondado": score_rounded,
        "interpretacao":    _get_interpretation(score_final),
        "aviso":            "Score é indicador de confiança, não certeza absoluta.",
    }
    if fp_block:
        breakdown["fp_warning"] = fp_block
    # Admiralty Code (P4): notação NATO de dois eixos, derivada do S e do C já
    # calculados. Não altera o score — é leitura padrão de SOC sobre a confiança.
    breakdown["admiralty"] = _admiralty_grade(best_source, S, fam_count, ioc, bool(fp_warning))
    return breakdown


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
