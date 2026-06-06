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

MEMÓRIA (Render free = 512 MB): IPs/domínios populares têm passive DNS de centenas
de milhares a milhões de registros — carregar a resposta inteira (`resp.text`) e
materializar uma lista de dicts estoura a RAM. A resposta é processada em STREAMING
(linha a linha) com agregação de memória LIMITADA: contagem, min/max de tempo, um
heap de tamanho fixo para as resoluções de maior volume e sets de contrapartes com
teto. TODOS os registros são lidos e contabilizados — nenhum é descartado da
agregação —, mas nunca ficam todos na memória ao mesmo tempo.
"""

import os
import json
import time
import heapq
import requests
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

_PDNS_QUERY = "https://www.circl.lu/pdns/query/{value}"
_TIMEOUT = 15
_SLEEP = 1.0                       # 1 req/s — respeita o fair use da CIRCL
_DEFAULT_MAX = 100                 # teto de consultas por execução (configurável)
_RECENT_DAYS = 30                  # "ainda ativo recentemente"
_MANY_PEERS = 50                   # > 50 contrapartes = possível bullet-proof/fast-flux
_TOP_N = 10                        # nº de resoluções de maior volume guardadas
_PEER_CAP = 2000                   # teto do set de contrapartes (memória) — > 50 já basta p/ suspeita
_NAME_CAP = 2000                   # teto p/ detecção de rrtypes conflitantes (memória)
_LINE_CAP = 5_000_000              # válvula de segurança absoluta (registros lidos por consulta)

_A_TYPES = ("A", "AAAA")
_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_NOT_FOUND = object()   # sentinel: API devolveu 404 (sem dados, não é erro de chamada)


class _RateLimit(Exception):
    """HTTP 429 ou timeout — aguarda 2 s antes da próxima chamada."""


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


def _to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _query_aggregate(value: str, is_ip: bool, auth: tuple[str, str]) -> dict | None:
    """Consulta o pDNS da CIRCL em STREAMING e agrega com memória LIMITADA.

    Lê a resposta NDJSON linha a linha (sem materializar `resp.text` nem a lista de
    registros) e mantém apenas agregados de tamanho fixo: contagem, min/max de tempo,
    heap das _TOP_N resoluções por volume, e sets de contrapartes/nomes com teto.
    Retorna o dict de campos pdns_* ou None (404/vazio/erro). Todos os registros são
    contabilizados; só não são retidos todos de uma vez."""
    try:
        resp = requests.get(_PDNS_QUERY.format(value=value), auth=auth,
                            timeout=_TIMEOUT, stream=True)
    except requests.exceptions.Timeout:
        raise _RateLimit("timeout")
    except Exception:
        return None

    try:
        if resp.status_code in (401, 403):
            raise _AuthError(f"HTTP {resp.status_code}")
        if resp.status_code == 404:
            return _NOT_FOUND
        if resp.status_code == 429:
            raise _RateLimit("429")
        resp.raise_for_status()

        count = 0
        first_ts = None
        last_ts = None
        peers: list[str] = []          # contrapartes únicas (ordem de chegada), com teto
        peers_set: set[str] = set()
        peers_overflow = False
        by_name: dict[str, set] = {}   # rrname -> {rrtypes} p/ conflito, com teto
        name_overflow = False
        top: list[tuple] = []          # min-heap [(count, seq, slim_record)]
        seq = 0

        try:
            for raw in resp.iter_lines(decode_unicode=True):
                if not raw:
                    continue
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    r = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    continue
                if not isinstance(r, dict):
                    continue

                count += 1
                if count > _LINE_CAP:      # válvula de segurança absoluta
                    break

                tf = _to_int(r.get("time_first"))
                tl = _to_int(r.get("time_last"))
                if tf is not None:
                    first_ts = tf if first_ts is None else min(first_ts, tf)
                if tl is not None:
                    last_ts = tl if last_ts is None else max(last_ts, tl)

                rrtype = (r.get("rrtype") or "").upper()
                cnt = _to_int(r.get("count")) or 0

                # Top-N por volume, sem guardar todos os registros (heap fixo).
                seq += 1
                slim = (r.get("rrtype"), r.get("rrname"), r.get("rdata"), cnt, tf, tl)
                if len(top) < _TOP_N:
                    heapq.heappush(top, (cnt, seq, slim))
                elif cnt > top[0][0]:
                    heapq.heapreplace(top, (cnt, seq, slim))

                # Contrapartes A/AAAA (IP=rrname, domínio=rdata na convenção CIRCL).
                if rrtype in _A_TYPES:
                    peer = r.get("rdata") if is_ip else r.get("rrname")
                    if peer and not peers_overflow and peer not in peers_set:
                        peers_set.add(peer)
                        peers.append(peer)
                        if len(peers_set) >= _PEER_CAP:
                            peers_overflow = True

                # Conflito de rrtype por rrname (bounded).
                name = r.get("rrname")
                if name and rrtype:
                    existing = by_name.get(name)
                    if existing is not None:
                        existing.add(rrtype)
                    elif not name_overflow:
                        by_name[name] = {rrtype}
                        if len(by_name) >= _NAME_CAP:
                            name_overflow = True
        except Exception:
            # Stream interrompido — segue com o que já foi agregado.
            pass
    except (_AuthError, _RateLimit):
        raise
    except Exception:
        return None
    finally:
        resp.close()

    if count == 0:
        return None

    top_sorted = sorted(top, key=lambda e: e[0], reverse=True)
    resolutions = [{
        "rrtype":     s[0],
        "rrname":     s[1],
        "rdata":      s[2],
        "count":      s[3],
        "time_first": _ts_to_date(s[4]),
        "time_last":  _ts_to_date(s[5]),
    } for (_c, _seq, s) in top_sorted]

    # --- Heurísticas de suspeita (a partir dos agregados) ---
    many_peers = peers_overflow or len(peers) > _MANY_PEERS
    recent = False
    if last_ts is not None:
        recent = (datetime.now(timezone.utc) - datetime.fromtimestamp(last_ts, tz=timezone.utc)) \
                 <= timedelta(days=_RECENT_DAYS)
    conflicting = any(len(types) > 1 for types in by_name.values())
    suspicious = bool(many_peers or recent or conflicting)

    return {
        "pdns_record_count":       count,
        "pdns_first_seen":         _ts_to_dt(first_ts),
        "pdns_last_seen":          _ts_to_dt(last_ts),
        "pdns_resolutions":        resolutions,
        "pdns_associated_ips":     peers[:20] if not is_ip else None,
        "pdns_associated_domains": peers[:20] if is_ip else None,
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
        sleep_s = 0.5   # padrão: 200 OK
        try:
            data = _query_aggregate(qval, target_map[qval]["is_ip"], auth)
        except _AuthError as e:
            print(f"[circl-pdns] ERRO de autenticação ({e}) — verifique CIRCL_USERNAME/"
                  f"CIRCL_PASSWORD; enricher interrompido (pipeline continua)")
            break
        except _RateLimit:
            sleep_s = 2.0
            data = None
        else:
            if data is _NOT_FOUND:
                sleep_s = 0.0   # 404 não consome orçamento — não precisa dormir
                data = None

        if data:
            enriched_at = datetime.now(timezone.utc)
            for ioc in target_map[qval]["iocs"]:
                ioc.update(data)
                ioc["pdns_enriched_at"] = enriched_at
            hit += 1
            if data.get("pdns_suspicious"):
                suspicious += 1
        if i < len(targets) - 1 and sleep_s > 0:
            time.sleep(sleep_s)

    print(f"[circl-pdns] {hit}/{len(targets)} alvos com dados ({suspicious} marcados suspicious)")
    return iocs
