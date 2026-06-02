"""Enriquecimento de domínios e URLs com RDAP (Registration Data Access Protocol).

RDAP é o substituto moderno do WHOIS — devolve JSON estruturado com datas de
registro/expiração, registradora e status do domínio. Tudo via endpoints
públicos sem API key, usando o bootstrap IANA para descobrir o servidor certo
por TLD: https://data.iana.org/rdap/dns.json

Valor para o score: domínio recém-registrado (< 30 dias) é sinal forte de
infraestrutura de ataque descartável — eleva o T dos domínios/URLs que não
tinham outro discriminador além do padrão fixo (60/65).

Não redundante com nenhum enricher existente: o Shodan cobre IPs; o RDAP cobre
o ciclo de vida do registro do domínio."""

import json
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse

_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_TIMEOUT = 8
_WORKERS = 8
_MAX_DOMAINS = 400

# Mapeamento TLD → servidor RDAP (cache em memória por processo).
_tld_servers: dict[str, str] = {}
_bootstrap_loaded = False


def _load_bootstrap() -> None:
    global _bootstrap_loaded
    if _bootstrap_loaded:
        return
    try:
        resp = requests.get(_BOOTSTRAP_URL, timeout=10)
        resp.raise_for_status()
        for entry in resp.json().get("services", []):
            tlds, servers = entry[0], entry[1]
            if not servers:
                continue
            srv = servers[0].rstrip("/") + "/"
            for tld in tlds:
                _tld_servers[tld.lower().lstrip(".")] = srv
        _bootstrap_loaded = True
    except Exception:
        _bootstrap_loaded = True   # não tenta de novo


def _rdap_server(domain: str) -> str | None:
    """Retorna a URL base do servidor RDAP para o TLD do domínio."""
    _load_bootstrap()
    parts = domain.lower().split(".")
    # tenta TLD de 2 partes primeiro (ex: .co.uk), depois simples (.com)
    for i in range(len(parts) - 1, 0, -1):
        tld = ".".join(parts[i:])
        if tld in _tld_servers:
            return _tld_servers[tld]
    return None


def _parse_date(val: str | None) -> datetime | None:
    if not val:
        return None
    val = val.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S+0000",
                "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d"):
        try:
            return datetime.strptime(val, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _domain_from_ioc(ioc: dict) -> str | None:
    """Extrai o FQDN do IOC (suporta type=domain e type=url)."""
    ioc_type = (ioc.get("type") or "").lower()
    value = (ioc.get("value") or "").strip()
    if ioc_type == "domain":
        return value.lower()
    if ioc_type == "url":
        try:
            host = urlparse(value if "://" in value else "http://" + value).hostname
            return host.lower() if host else None
        except Exception:
            return None
    return None


def _lookup(domain: str) -> tuple[str, dict | None]:
    """Consulta o RDAP para `domain`. Retorna (domain, dados|None)."""
    try:
        server = _rdap_server(domain)
        if not server:
            return domain, None
        resp = requests.get(f"{server}domain/{domain}", timeout=_TIMEOUT,
                            headers={"Accept": "application/rdap+json"})
        if resp.status_code in (404, 400):
            return domain, None
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return domain, None

    # Extrai eventos relevantes
    registered = expiration = last_changed = None
    for ev in data.get("events") or []:
        action = (ev.get("eventAction") or "").lower()
        date   = _parse_date(ev.get("eventDate"))
        if action in ("registration",):
            registered = date
        elif action in ("expiration",):
            expiration = date
        elif action in ("last changed", "last update of rdap database"):
            last_changed = date

    # Status
    status = [s for s in (data.get("status") or []) if s]

    # Registradora (primeira entidade com role "registrar")
    registrar = None
    for ent in data.get("entities") or []:
        roles = [r.lower() for r in (ent.get("roles") or [])]
        if "registrar" in roles:
            vcard = ent.get("vcardArray") or []
            if vcard and len(vcard) > 1:
                for prop in vcard[1]:
                    if prop[0] == "fn":
                        registrar = prop[3]
                        break
            break

    # Idade em dias (a partir do registro)
    age_days = None
    if registered:
        age_days = (datetime.now(timezone.utc) - registered).days

    result = {
        "registered":   registered.strftime("%Y-%m-%d") if registered else None,
        "expiration":   expiration.strftime("%Y-%m-%d") if expiration else None,
        "last_changed": last_changed.strftime("%Y-%m-%d") if last_changed else None,
        "registrar":    registrar,
        "status":       status[:4],       # teto para não inflar o JSON
        "age_days":     age_days,
    }
    # Só retorna se tem pelo menos a data de registro
    return domain, (result if result["registered"] else None)


def enrich_batch(iocs: list[dict]) -> list[dict]:
    """Enriquece domínios e URLs com dados RDAP (in-place).
    Seta ioc['rdap_data'] (dict) quando encontra registro."""
    targets = [
        ioc for ioc in iocs
        if (ioc.get("type") or "").lower() in ("domain", "url")
        and _domain_from_ioc(ioc)
    ]
    if not targets:
        return iocs

    # Agrupa por FQDN (várias URLs podem ter o mesmo host)
    domain_map: dict[str, list[dict]] = {}
    for ioc in targets:
        d = _domain_from_ioc(ioc)
        if d:
            domain_map.setdefault(d, []).append(ioc)

    domains = list(domain_map)[:_MAX_DOMAINS]
    print(f"[rdap] consultando RDAP para {len(domains)} domínios")

    hit = 0
    with ThreadPoolExecutor(max_workers=_WORKERS) as ex:
        futures = [ex.submit(_lookup, d) for d in domains]
        for fut in as_completed(futures):
            domain, data = fut.result()
            if data:
                for ioc in domain_map[domain]:
                    ioc["rdap_data"] = data
                hit += 1

    print(f"[rdap] {hit}/{len(domains)} domínios com dados RDAP")
    return iocs
