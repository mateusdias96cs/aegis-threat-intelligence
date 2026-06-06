"""
Enriquecimento com CIRCL Passive SSL (https://www.circl.lu/services/passive-ssl/).

Passive SSL é um banco histórico de certificados X.509 observados por IP. Permite
rastrear infraestrutura de atacante mesmo quando ele troca de domínio (pivotamento
por fingerprint de certificado) e identificar IPs que compartilharam o mesmo cert.

Aplica-se APENAS a IOCs do tipo `ip`. Requer credenciais (CIRCL_USERNAME /
CIRCL_PASSWORD) via HTTP Basic Auth. Sem credenciais, é pulado silenciosamente
(degradação graciosa).

Formato real da API (confirmado ao vivo):
  /v2pssl/query/{ip}   -> {"<ip>": {"certificates": ["<sha1>", ...],
                                     "subjects": {"<sha1>": {"values": ["<DN>"]}}}}
  /v2pssl/cfetch/{sha1}-> {"info": {"subject": "<DN string>", "issuer": "<DN string>",
                                    "not_before": "...", "not_after": "...",
                                    "extension": {"subjectAltName": "DNS:a, DNS:b"}}}
Os DNs (subject/issuer) vêm como STRING ("C=US, O=..., CN=..."), não objeto.

Fair use: chamadas SEQUENCIAIS — 1 s entre /query, 0,5 s entre /cfetch. Teto de IPs
por execução (CIRCL_MAX_LOOKUPS), priorizando os de maior abuse_score/severidade.
"""

import os
import re
import json
import time
import requests
from datetime import datetime, timezone

_PSSL_QUERY  = "https://www.circl.lu/v2pssl/query/{ip}"
_PSSL_CFETCH = "https://www.circl.lu/v2pssl/cfetch/{sha1}"
_TIMEOUT = 15
_SLEEP_QUERY  = 1.0
_SLEEP_CFETCH = 0.5
_DEFAULT_MAX = 100
_FETCH_CERTS = 3                   # detalha os 3 primeiros fingerprints
_MANY_CERTS = 10                   # > 10 certs = infraestrutura rotativa
_LONG_VALIDITY_DAYS = 365 * 5      # validade > 5 anos = geração automatizada suspeita

_CN_RE  = re.compile(r"CN=([^,/]+)")
_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_NOT_FOUND = object()   # sentinel: API devolveu 404


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


def _cn(dn: str | None) -> str | None:
    """Extrai o CommonName de uma string DN ('C=US, O=..., CN=foo') ."""
    if not dn:
        return None
    m = _CN_RE.search(dn)
    return m.group(1).strip() if m else None


def _parse_dt(val: str | None) -> datetime | None:
    if not val:
        return None
    val = val.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(val)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(val, fmt)
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def _parse_san(ext: dict | None) -> list[str]:
    """subjectAltName vem como 'DNS:a.com, DNS:www.a.com, IP:1.2.3.4'."""
    if not isinstance(ext, dict):
        return []
    raw = ext.get("subjectAltName") or ext.get("subjectAltname") or ""
    out = []
    for part in str(raw).split(","):
        part = part.strip()
        if ":" in part:
            part = part.split(":", 1)[1].strip()
        if part:
            out.append(part)
    return list(dict.fromkeys(out))


def _query(ip: str, auth: tuple[str, str]):
    """Lista os certificados vistos num IP. Retorna o sub-dict do IP, _NOT_FOUND ou None."""
    try:
        resp = requests.get(_PSSL_QUERY.format(ip=ip), auth=auth, timeout=_TIMEOUT)
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
        data = resp.json()
    except (_AuthError, _RateLimit):
        raise
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    node = data.get(ip) or (next(iter(data.values()), None) if data else None)
    return node if isinstance(node, dict) and node.get("certificates") else None


def _cfetch(sha1: str, auth: tuple[str, str]) -> dict | None:
    """Detalha um certificado pelo fingerprint SHA1."""
    try:
        resp = requests.get(_PSSL_CFETCH.format(sha1=sha1), auth=auth, timeout=_TIMEOUT)
        if resp.status_code in (401, 403):
            raise _AuthError(f"HTTP {resp.status_code}")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        info = (resp.json() or {}).get("info")
        return info if isinstance(info, dict) else None
    except _AuthError:
        raise
    except Exception:
        return None


def _analyze(ip: str, node: dict, auth: tuple[str, str]) -> dict | None:
    fingerprints = [f for f in (node.get("certificates") or []) if f]
    if not fingerprints:
        return None

    now = datetime.now(timezone.utc)
    certs_out: list[dict] = []
    subjects: set[str] = set()
    self_signed = expired = long_validity = False

    # CNs já disponíveis no map "subjects" da própria /query (sem custo extra).
    for entry in (node.get("subjects") or {}).values():
        for dn in (entry.get("values") or []) if isinstance(entry, dict) else []:
            cn = _cn(dn)
            if cn:
                subjects.add(cn)

    for sha1 in fingerprints[:_FETCH_CERTS]:
        info = _cfetch(sha1, auth)
        time.sleep(_SLEEP_CFETCH)
        if not info:
            continue
        subject_dn = info.get("subject")
        issuer_dn  = info.get("issuer")
        nb = _parse_dt(info.get("not_before"))
        na = _parse_dt(info.get("not_after"))
        san = _parse_san(info.get("extension"))

        if subject_dn and issuer_dn and subject_dn.strip() == issuer_dn.strip():
            self_signed = True
        if na and na < now:
            expired = True
        if nb and na and (na - nb).days > _LONG_VALIDITY_DAYS:
            long_validity = True

        s_cn = _cn(subject_dn)
        if s_cn:
            subjects.add(s_cn)

        certs_out.append({
            "fingerprint": sha1,
            "subject_cn":  s_cn,
            "issuer_cn":   _cn(issuer_dn),
            "valid_from":  nb.strftime("%Y-%m-%d") if nb else None,
            "valid_to":    na.strftime("%Y-%m-%d") if na else None,
            "san":         san[:20],
        })

    cert_count = len(fingerprints)
    suspicious = bool(self_signed or cert_count > _MANY_CERTS or long_validity)

    return {
        "pssl_cert_count":   cert_count,
        "pssl_certificates": certs_out,
        "pssl_subjects":     sorted(subjects)[:30],
        "pssl_self_signed":  self_signed,
        "pssl_expired":      expired,
        "pssl_suspicious":   suspicious,
    }


def enrich_batch(iocs: list[dict]) -> list[dict]:
    """Enriquece IOCs do tipo ip com CIRCL Passive SSL (in-place, sequencial)."""
    auth = _auth()
    if not auth:
        print("[circl-pssl] sem CIRCL_USERNAME/CIRCL_PASSWORD no ambiente — pSSL ignorado")
        return iocs

    ip_map: dict[str, list[dict]] = {}
    for ioc in iocs:
        if (ioc.get("type") or "").lower() != "ip":
            continue
        ip = (ioc.get("value") or "").split(":")[0].strip()
        if ip:
            ip_map.setdefault(ip, []).append(ioc)

    if not ip_map:
        return iocs

    def _priority(ip: str) -> tuple:
        peers = ip_map[ip]
        abuse = max((p.get("abuse_score") or 0) for p in peers)
        sev   = min(_SEV_RANK.get((p.get("severity") or "").upper(), 9) for p in peers)
        return (-abuse, sev)

    ips = sorted(ip_map, key=_priority)[:_max_lookups()]
    print(f"[circl-pssl] consultando Passive SSL para {len(ips)} IPs "
          f"(de {len(ip_map)}; teto={_max_lookups()})")

    hit = suspicious = 0
    for i, ip in enumerate(ips):
        sleep_s = 0.5   # padrão: 200 OK
        try:
            node = _query(ip, auth)
        except _AuthError as e:
            print(f"[circl-pssl] ERRO de autenticação ({e}) — verifique CIRCL_USERNAME/"
                  f"CIRCL_PASSWORD; enricher interrompido (pipeline continua)")
            break
        except _RateLimit:
            sleep_s = 2.0
            node = None
        else:
            if node is _NOT_FOUND:
                sleep_s = 0.0
                node = None

        if node:
            data = _analyze(ip, node, auth)
            if data:
                enriched_at = datetime.now(timezone.utc)
                for ioc in ip_map[ip]:
                    ioc.update(data)
                    ioc["pssl_enriched_at"] = enriched_at
                hit += 1
                if data.get("pssl_suspicious"):
                    suspicious += 1
        if i < len(ips) - 1 and sleep_s > 0:
            time.sleep(sleep_s)

    print(f"[circl-pssl] {hit}/{len(ips)} IPs com certificados ({suspicious} marcados suspicious)")
    return iocs
