"""Baixa um conjunto curado de warninglists do MISP para data/warninglists/.

Listas escolhidas pelo maior impacto em falso-positivo de IOC: faixas de
cloud/CDN (um IP da AWS/Cloudflare quase nunca é "o atacante", e sim um
serviço hospedado), resolvers DNS públicos, redes reservadas/bogon e domínios
populares (Tranco top — improvável serem maliciosos).

Fonte: https://github.com/MISP/misp-warninglists (CC0). Rode periodicamente
Uso: .venv/bin/python -m src.scripts.refresh_warninglists
"""

import sys
from pathlib import Path

import requests

_RAW = "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/{}/list.json"

# nome-da-pasta-no-repo : arquivo-de-saída
_CURATED = {
    "amazon-aws":          "amazon-aws",
    "microsoft-azure":     "microsoft-azure",
    "google-gcp":          "google-gcp",
    "cloudflare":          "cloudflare",
    "akamai":              "akamai",
    "fastly":              "fastly",
    "public-dns-v4":       "public-dns-v4",
    "rfc1918":             "rfc1918",            # redes privadas
    "rfc5735":             "rfc5735",            # reservadas/bogon
    "tranco10k":           "tranco10k",          # top 10k domínios populares (conservador)
    "google":              "google-domains",     # domínios do Google
    "microsoft-office365": "microsoft-o365",
}

_OUT = Path(__file__).resolve().parent.parent.parent / "data" / "warninglists"


def run() -> int:
    _OUT.mkdir(parents=True, exist_ok=True)
    ok, fail = 0, 0
    for repo_name, out_name in _CURATED.items():
        url = _RAW.format(repo_name)
        try:
            r = requests.get(url, timeout=20)
            if r.status_code != 200:
                print(f"  [skip] {repo_name}: HTTP {r.status_code}")
                fail += 1
                continue
            # valida que é JSON e tem 'list'
            data = r.json()
            n = len(data.get("list") or [])
            (_OUT / f"{out_name}.json").write_text(r.text, encoding="utf-8")
            print(f"  [ok]   {repo_name}: {n} entradas -> {out_name}.json")
            ok += 1
        except Exception as e:
            print(f"  [fail] {repo_name}: {e}")
            fail += 1
    print(f"\nwarninglists atualizadas: {ok} ok, {fail} falhas, dir={_OUT}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(run())
