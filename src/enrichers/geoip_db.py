"""Resolução e provisionamento dos bancos GeoLite2 (MaxMind) para enriquecimento de IP.

Por que este módulo existe — contexto do Render (free tier):
O Render usa filesystem EFÊMERO: tudo que não está no repositório some a cada
deploy/restart. Os .mmdb da MaxMind não são versionados (licença + tamanho), então
o path fixo do `.env` (`./data/GeoLite2-Country_20260529/...`) aponta para um arquivo
que NÃO existe em produção — daí o erro recorrente
"[ip_enricher] GeoIP2 reader failed to open: No such file or directory".
Pior: o nome da pasta carrega a DATA do download, então mesmo baixando de novo o
path hardcoded já nasce desatualizado no ciclo seguinte.

A estratégia aqui:
  1. RESOLVER por glob (`find_mmdb`) — acha qualquer .mmdb da edição em data/,
     independente da data no nome da pasta. Mata o acoplamento ao path datado.
  2. PROVISIONAR sob demanda (`ensure_geoip_db`) — se o .mmdb não existe e há
     `MAXMIND_LICENSE_KEY`, baixa da MaxMind na inicialização do pipeline.
  3. DEGRADAR com graça — sem a chave (ou se o download falhar), o enrichment
     geográfico é apenas desabilitado (country/asn = None), nunca uma exception.
"""

import glob
import os
import shutil
import tarfile
import tempfile

import requests

# Endpoint de download permalink da MaxMind (exige conta gratuita + license key).
_MAXMIND_URL = "https://download.maxmind.com/app/geoip_download"

# edição lógica → (edition_id da MaxMind, env var que o resto do código consome)
_EDITIONS: dict[str, tuple[str, str]] = {
    "country": ("GeoLite2-Country", "MAXMIND_DB_PATH"),
    "asn":     ("GeoLite2-ASN",     "MAXMIND_ASN_DB_PATH"),
}

# Pasta onde os .mmdb vivem. Mantém a convenção atual (./data) e é configurável.
_DATA_DIR = os.getenv("GEOIP_DATA_DIR", "./data")


def find_mmdb(edition_id: str) -> str | None:
    """Retorna o caminho de um .mmdb da edição em data/, ou None se não houver.

    Procura recursivamente por `{edition_id}*.mmdb` — casa tanto a pasta datada
    (`GeoLite2-Country_20260529/GeoLite2-Country.mmdb`) quanto a pasta estável que
    `_download_edition` cria. A data está no nome da PASTA, então a ordem lexical
    dos caminhos equivale à ordem cronológica: pegamos o mais recente.
    """
    pattern = os.path.join(_DATA_DIR, "**", f"{edition_id}*.mmdb")
    matches = sorted(glob.glob(pattern, recursive=True))
    return matches[-1] if matches else None


def _download_edition(edition_id: str, license_key: str) -> str | None:
    """Baixa e extrai um .mmdb da MaxMind para uma pasta estável. None em qualquer falha.

    Extrai para `data/{edition_id}/{edition_id}.mmdb` (path SEM data) — assim o
    `find_mmdb` o encontra nos próximos runs sem depender de quando foi baixado.
    """
    params = {"edition_id": edition_id, "license_key": license_key, "suffix": "tar.gz"}
    try:
        resp = requests.get(_MAXMIND_URL, params=params, timeout=60)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[geoip] download de {edition_id} falhou: {e}")
        return None

    dest_dir = os.path.join(_DATA_DIR, edition_id)
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, f"{edition_id}.mmdb")

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            tmp.write(resp.content)
            tmp_path = tmp.name
        with tarfile.open(tmp_path, "r:gz") as tar:
            member = next((m for m in tar.getmembers() if m.name.endswith(".mmdb")), None)
            if member is None:
                print(f"[geoip] nenhum .mmdb dentro do pacote de {edition_id}")
                return None
            extracted = tar.extractfile(member)
            if extracted is None:
                return None
            with extracted as src, open(dest_path, "wb") as out:
                shutil.copyfileobj(src, out)
    except Exception as e:
        print(f"[geoip] falha ao extrair {edition_id}: {e}")
        return None
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    print(f"[geoip] {edition_id} baixado → {dest_path}")
    return dest_path


def ensure_geoip_db() -> None:
    """Garante os .mmdb na inicialização e exporta os paths resolvidos via env var.

    Para cada edição (Country, ASN):
      • se já existe um .mmdb (glob) → usa e aponta a env var para o caminho real;
      • se falta e há MAXMIND_LICENSE_KEY → baixa da MaxMind;
      • se falta e não há chave (ou download falhou) → desabilita a edição
        (remove a env var) para que o enricher caia no fallback silencioso.

    Idempotente e à prova de Render: chamar a cada run reanexa os arquivos (que
    podem ter sumido no restart) sem nunca lançar exception.
    """
    license_key = os.getenv("MAXMIND_LICENSE_KEY")

    for edition_id, env_var in _EDITIONS.values():
        path = find_mmdb(edition_id)
        if path:
            os.environ[env_var] = path
            print(f"[geoip] usando {edition_id} existente: {path}")
            continue

        if not license_key:
            # Sem a chave o path do .env (se houver) aponta para arquivo inexistente;
            # remover a env var evita o erro de open e ativa o fallback gracioso.
            os.environ.pop(env_var, None)
            print(f"[geoip] {edition_id} ausente e MAXMIND_LICENSE_KEY não definida — "
                  f"enriquecimento geográfico/ASN desabilitado (fallback gracioso)")
            continue

        path = _download_edition(edition_id, license_key)
        if path:
            os.environ[env_var] = path
        else:
            os.environ.pop(env_var, None)
            print(f"[geoip] {edition_id} indisponível — seguindo sem ele")
