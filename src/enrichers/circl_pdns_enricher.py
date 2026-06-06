"""
Enriquecimento com CIRCL Passive DNS (https://www.circl.lu/services/passive-dns/).

Passive DNS é um banco histórico de resoluções DNS observadas no mundo real:
para um domínio, quais IPs ele já apontou; para um IP, quais domínios já hospedou,
desde quando e com que frequência. Dá ao analista pivotamento por infraestrutura
e janela temporal REAL — algo que nenhum feed de blocklist carrega.

Requer credenciais (CIRCL_USERNAME / CIRCL_PASSWORD) via HTTP Basic Auth — acesso
de parceiro confiável da CIRCL. Sem as credenciais o enricher é pulado
silenciosamente (degradação graciosa — o pipeline continua e o IOC é salvo sem
os dados de pDNS).

IMPORTANTE — convenção de campos da CIRCL: ao contrário do exemplo "clássico" de
passive DNS, a CIRCL devolve, para registros A/AAAA, `rrname` = ENDEREÇO (o IP) e
`rdata` = NOME (o domínio). Confirmado ao vivo contra a API. O parser abaixo trata
o IP sempre como `rrname` e o domínio sempre como `rdata` para A/AAAA.

Fair use: chamadas SEQUENCIAIS, 1 req/s, sem threading (a CIRCL suspende contas
por abuso). Há um teto de consultas por execução (CIRCL_MAX_LOOKUPS) — os alvos de
maior valor (maior abuse_score / severidade) são priorizados; a cobertura cresce
ao longo de várias execuções.
"""

import os
import json
import time
import requests
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

_PDNS_QUERY = "https://www.circl.lu/pdns/query/{value}"
_TIMEOUT = 15
_SLEEP = 1.0                       # 1 req/s — respeita o fair use da CIRCL
_DEFAULT_MAX = 100                 # teto de consultas por execução (configurável)
_RECENT_DAYS = 30                  # "ainda ativo recentemente"
_MANY_PEERS = 50                   # > 50 contrapartes = possível bullet-proof/fast-flux

_A_TYPES = ("A", "AAAA")
_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _auth() -> tuple[str, str] | None:
    u, p = os.getenv("CIRCL_USERNAME"), os.getenv("CIRCL_PASSWORD")
    return (u, p) if (u and p) else None


def _max_lookups() -> int:
    try:
        return max(0, int(os.getenv("CIRCL_MAX_LOOKUPS", str(_DEFAULT_MAX))))
    except ValueError:
        return _DEFAULT_MAX


class _AuthError(Exception):
    """Credenciais rejeitadas (401/403) — interrompe o enricher, não o pipeline."""


def _domain_from_ioc(ioc: dict) -> str | None:
    """FQDN a consultar: o próprio domínio, ou o host extraído da URL."""
    value = (ioc.get("value") or "").strip()
    ioc_type = (ioc.get("type") or "").lower()
    if ioc_type == "domain":
        return value.lower() or None
    if ioc_type == "url":
        try:
            host = urlparse(value if "://" in value else "http://" + value).hostname
            return host.lower() if host else None
        except Exception:
            return None
    return None


def _query_target(ioc: dict) -> tuple[str, bool] | None:
    """Retorna (valor_a_consultar, is_ip) ou None se o tipo não se aplica."""
    ioc_type = (ioc.get("type") or "").lower()
    if ioc_type == "ip":
        ip = (ioc.get("value") or "").split(":")[0].strip()
        return (ip, True) if ip else None
    dom = _domain_from_ioc(ioc)
    return (dom, False) if dom else None


def _parse_ndjson(text_body: str) -> list[dict]:
    """Parse robusto de NDJSON — uma linha malformada não derruba o resto."""
    records = []
    for line in text_body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                records.append(obj)
        except (json.JSONDecodeError, TypeError):
            continue
    return records


def _ts_to_date(ts) -> str | None:
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OSError):
        return None


def _ts_to_dt(ts) -> datetime | None:
    """Unix timestamp → datetime (colunas TIMESTAMP aceitam objeto datetime em
    SQLite e PostgreSQL; strings ISO não passam pelo type-coercion do SQLite)."""
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return None


def _query(value: str, auth: tuple[str, str]) -> list[dict] | None:
    """Consulta o pDNS da CIRCL. Retorna lista de registros ou None (404/vazio)."""
    try:
        resp = requests.get(_PDNS_QUERY.format(value=value), auth=auth, timeout=_TIMEOUT)
        if resp.status_code in (401, 403):
            raise _AuthError(f"HTTP {resp.status_code}")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        records = _parse_ndjson(resp.text)
        return records or None
    except _AuthError:
        raise
    except Exception:
        return None


def _analyze(records: list[dict], is_ip: bool) -> dict | None:
    """Condensa os registros de pDNS nos campos persistidos no IOC."""
    # Dedup por (rrname, rrtype, rdata) — "registros históricos únicos".
    uniq: dict[tuple, dict] = {}
    for r in records:
        key = (r.get("rrname"), r.get("rrtype"), r.get("rdata"))
        prev = uniq.get(key)
        if prev is None:
            uniq[key] = r
        else:
            # Mantém o de maior count / janela temporal mais ampla.
            prev["count"] = max(prev.get("count") or 0, r.get("count") or 0)
            prev["time_first"] = min(prev.get("time_first") or r.get("time_first") or 0,
                                     r.get("time_first") or prev.get("time_first") or 0)
            prev["time_last"] = max(prev.get("time_last") or 0, r.get("time_last") or 0)
    recs = list(uniq.values())
    if not recs:
        return None

    times_first = [r.get("time_first") for r in recs if r.get("time_first")]
    times_last  = [r.get("time_last") for r in recs if r.get("time_last")]
    first_ts = min(times_first) if times_first else None
    last_ts  = max(times_last) if times_last else None

    # A/AAAA: na convenção CIRCL, IP = rrname, domínio = rdata.
    a_records = [r for r in recs if (r.get("rrtype") or "").upper() in _A_TYPES]
    assoc_ips     = list(dict.fromkeys(r.get("rrname") for r in a_records if r.get("rrname")))
    assoc_domains = list(dict.fromkeys(r.get("rdata") for r in a_records if r.get("rdata")))

    # Top 10 resoluções por volume observado (auditável: mantém os dois lados).
    top = sorted(recs, key=lambda r: (r.get("count") or 0), reverse=True)[:10]
    resolutions = [{
        "rrtype":     r.get("rrtype"),
        "rrname":     r.get("rrname"),
        "rdata":      r.get("rdata"),
        "count":      r.get("count"),
        "time_first": _ts_to_date(r.get("time_first")),
        "time_last":  _ts_to_date(r.get("time_last")),
    } for r in top]

    # --- Heurísticas de suspeita ---
    # (a) muitas contrapartes: p/ IP = nº de domínios hospedados; p/ domínio = nº de IPs.
    peer_count = len(assoc_domains) if is_ip else len(assoc_ips)
    many_peers = peer_count > _MANY_PEERS
    # (b) atividade recente (visto nos últimos 30 dias).
    recent = False
    if last_ts:
        recent = (datetime.now(timezone.utc) - datetime.fromtimestamp(int(last_ts), tz=timezone.utc)) \
                 <= timedelta(days=_RECENT_DAYS)
    # (c) rrtypes conflitantes para o mesmo rrname (mesma entidade com tipos divergentes).
    by_name: dict[str, set] = {}
    for r in recs:
        name = r.get("rrname")
        if name:
            by_name.setdefault(name, set()).add((r.get("rrtype") or "").upper())
    conflicting = any(len(types) > 1 for types in by_name.values())

    suspicious = bool(many_peers or recent or conflicting)

    return {
        "pdns_record_count":       len(recs),
        "pdns_first_seen":         _ts_to_dt(first_ts),
        "pdns_last_seen":          _ts_to_dt(last_ts),
        "pdns_resolutions":        resolutions,
        "pdns_associated_ips":     assoc_ips[:20] if not is_ip else None,
        "pdns_associated_domains": assoc_domains[:20] if is_ip else None,
        "pdns_suspicious":         suspicious,
    }


def enrich_batch(iocs: list[dict]) -> list[dict]:
    """Enriquece IOCs (domain/ip/url) com CIRCL Passive DNS (in-place, sequencial)."""
    auth = _auth()
    if not auth:
        print("[circl-pdns] sem CIRCL_USERNAME/CIRCL_PASSWORD no ambiente — pDNS ignorado")
        return iocs

    # Agrupa por valor de consulta (dedup) e preserva ponteiros p/ os IOCs.
    target_map: dict[str, dict] = {}   # query_value -> {"is_ip": bool, "iocs": [...]}
    for ioc in iocs:
        if (ioc.get("type") or "").lower() not in ("domain", "ip", "url"):
            continue
        t = _query_target(ioc)
        if not t:
            continue
        qval, is_ip = t
        slot = target_map.setdefault(qval, {"is_ip": is_ip, "iocs": []})
        slot["iocs"].append(ioc)

    if not target_map:
        return iocs

    # Prioriza alvos de maior valor (abuse_score, depois severidade) sob o teto.
    def _priority(qval: str) -> tuple:
        peers = target_map[qval]["iocs"]
        abuse = max((p.get("abuse_score") or 0) for p in peers)
        sev   = min(_SEV_RANK.get((p.get("severity") or "").upper(), 9) for p in peers)
        return (-abuse, sev)

    targets = sorted(target_map, key=_priority)[:_max_lookups()]
    print(f"[circl-pdns] consultando Passive DNS para {len(targets)} alvos "
          f"(de {len(target_map)}; teto={_max_lookups()})")

    hit = suspicious = 0
    for i, qval in enumerate(targets):
        try:
            records = _query(qval, auth)
        except _AuthError as e:
            print(f"[circl-pdns] ERRO de autenticação ({e}) — verifique CIRCL_USERNAME/"
                  f"CIRCL_PASSWORD; enricher interrompido (pipeline continua)")
            break
        if records:
            data = _analyze(records, target_map[qval]["is_ip"])
            if data:
                enriched_at = datetime.now(timezone.utc)
                for ioc in target_map[qval]["iocs"]:
                    ioc.update(data)
                    ioc["pdns_enriched_at"] = enriched_at
                hit += 1
                if data.get("pdns_suspicious"):
                    suspicious += 1
        # Pausa entre chamadas (não dorme após a última).
        if i < len(targets) - 1:
            time.sleep(_SLEEP)

    print(f"[circl-pdns] {hit}/{len(targets)} alvos com dados ({suspicious} marcados suspicious)")
    return iocs
