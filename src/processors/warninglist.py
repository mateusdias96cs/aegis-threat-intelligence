"""Warninglists / known-good infrastructure (P2).

Reduz falso-positivo cruzando cada IOC contra listas curadas de infraestrutura
LEGÍTIMA conhecida (faixas de cloud/CDN, resolvers DNS públicos, redes
reservadas e domínios populares — Tranco). Não DELETA nada: marca o IOC com o
nome da lista que casou (`fp_warning`), o que sinaliza ao analista e penaliza o
score (ver classifier.calculate_score_breakdown).

Formato das listas: JSON do projeto MISP/misp-warninglists
(https://github.com/MISP/misp-warninglists), um arquivo por lista em
`data/warninglists/<nome>.json`:

    {"name": "...", "type": "cidr"|"string"|"substring"|"hostname",
     "matching_attributes": [...], "list": ["52.0.0.0/11", "example.com", ...]}

Degrada graciosamente: se o diretório não existir ou estiver vazio, o checker
não marca nada (igual ao geoip2 ausente). Use `src/scripts/refresh_warninglists.py`
para baixar as listas."""

import ipaddress
import json
from pathlib import Path

_DEFAULT_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "warninglists"


class WarningListChecker:
    """Carrega as listas uma vez e responde `check(ioc)` em tempo ~constante.

    - IPs: redes CIDR agrupadas pelo 1º octeto (poda a busca de O(redes) para
      O(redes do octeto)).
    - Domínios/URLs: conjunto de domínios exatos + checagem de sufixo de domínio
      pai (sub.example.com casa example.com)."""

    def __init__(self, lists_dir: Path | str = _DEFAULT_DIR):
        self._dir = Path(lists_dir)
        # IPv4: octeto inicial -> [(ip_network, list_name)]
        self._cidr_by_octet: dict[int, list[tuple]] = {}
        self._cidr_v6: list[tuple] = []
        # domínio exato -> list_name ; e sufixos (mesmo dict, casamento por pai)
        self._domains: dict[str, str] = {}
        self._loaded_lists: list[str] = []
        self._load()

    # ── carga ────────────────────────────────────────────────────────────────
    def _load(self) -> None:
        if not self._dir.is_dir():
            return
        for path in sorted(self._dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            name = data.get("name") or path.stem
            entries = data.get("list") or []
            ltype = (data.get("type") or "").lower()
            self._ingest(name, ltype, entries)
            self._loaded_lists.append(name)

    def _ingest(self, name: str, ltype: str, entries: list) -> None:
        for raw in entries:
            val = (str(raw) or "").strip()
            if not val:
                continue
            # CIDR / IP explícito
            if ltype == "cidr" or "/" in val or _looks_like_ip(val):
                try:
                    net = ipaddress.ip_network(val, strict=False)
                except ValueError:
                    # não é rede — trata como domínio
                    self._domains.setdefault(_norm_domain(val), name)
                    continue
                if net.version == 4:
                    octet = int(str(net.network_address).split(".", 1)[0])
                    self._cidr_by_octet.setdefault(octet, []).append((net, name))
                else:
                    self._cidr_v6.append((net, name))
            else:
                self._domains.setdefault(_norm_domain(val), name)

    # ── consulta ──────────────────────────────────────────────────────────────
    @property
    def loaded(self) -> bool:
        return bool(self._loaded_lists)

    @property
    def lists(self) -> list[str]:
        return list(self._loaded_lists)

    def check(self, ioc: dict) -> str | None:
        """Retorna o nome da lista de infra legítima que casa o IOC, ou None."""
        if not self.loaded:
            return None
        ioc_type = (ioc.get("type") or "").lower()
        value = ioc.get("value") or ""
        if ioc_type == "ip":
            return self._check_ip(value)
        if ioc_type in ("domain", "url"):
            host = _host_from_url(value) if ioc_type == "url" else value
            return self._check_domain(host)
        return None

    def _check_ip(self, value: str) -> str | None:
        ip_str = (value or "").split(":")[0] if value.count(".") == 3 else value
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return None
        if ip.version == 4:
            octet = int(str(ip).split(".", 1)[0])
            for net, name in self._cidr_by_octet.get(octet, ()):  # poda por octeto
                if ip in net:
                    return name
        else:
            for net, name in self._cidr_v6:
                if ip in net:
                    return name
        return None

    def _check_domain(self, host: str) -> str | None:
        host = _norm_domain(host)
        if not host:
            return None
        # exato
        if host in self._domains:
            return self._domains[host]
        # sufixo: sub.a.example.com -> tenta a.example.com -> example.com
        parts = host.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self._domains:
                return self._domains[parent]
        return None

    def annotate(self, iocs: list[dict]) -> list[dict]:
        """Seta ioc['fp_warning'] in-place para o lote. No-op se não há listas."""
        if not self.loaded:
            return iocs
        for ioc in iocs:
            hit = self.check(ioc)
            if hit:
                ioc["fp_warning"] = hit
        return iocs


# ── helpers ────────────────────────────────────────────────────────────────────
def _looks_like_ip(val: str) -> bool:
    return val.count(".") == 3 and all(p.isdigit() for p in val.split(".") if p)


def _norm_domain(val: str) -> str:
    val = (val or "").strip().lower().rstrip(".")
    if val.startswith("*."):
        val = val[2:]
    return val


def _host_from_url(url: str) -> str:
    s = (url or "").strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]
    s = s.split("@")[-1]      # remove userinfo
    s = s.split(":", 1)[0]    # remove porta
    return s


# ── singleton lazy (carregado uma vez por processo) ─────────────────────────────
_checker: WarningListChecker | None = None


def get_checker() -> WarningListChecker:
    global _checker
    if _checker is None:
        _checker = WarningListChecker()
    return _checker


def annotate(iocs: list[dict]) -> list[dict]:
    return get_checker().annotate(iocs)
