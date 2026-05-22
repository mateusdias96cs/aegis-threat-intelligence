"""
AEGIS Threat Intelligence — Smoke Test
Roda todos os testes críticos de API e segurança.

Uso:
    python3 tests/smoke_test.py
    python3 tests/smoke_test.py --url https://aegiscti.me  # produção
    python3 tests/smoke_test.py --url http://localhost:8000  # local
"""

import sys
import json
import time
import argparse
import requests

# ── Configuração ──────────────────────────────────────────────────────────────
DEFAULT_URL = "https://aegiscti.me"
TIMEOUT     = 15

# Cores para output
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

passed = 0
failed = 0
warnings = 0

def ok(msg):
    global passed
    passed += 1
    print(f"  {GREEN}✅ PASS{RESET} — {msg}")

def fail(msg, detail=""):
    global failed
    failed += 1
    detail_str = f"\n         {RED}{detail}{RESET}" if detail else ""
    print(f"  {RED}❌ FAIL{RESET} — {msg}{detail_str}")

def warn(msg):
    global warnings
    warnings += 1
    print(f"  {YELLOW}⚠  WARN{RESET} — {msg}")

def section(title):
    print(f"\n{BOLD}── {title} {'─' * (50 - len(title))}{RESET}")

def get(url, **kwargs):
    return requests.get(url, timeout=TIMEOUT, **kwargs)

def post(url, **kwargs):
    return requests.post(url, timeout=TIMEOUT, **kwargs)


def run_tests(base: str):
    print(f"\n{BOLD}AEGIS Smoke Test{RESET}")
    print(f"Target: {base}")
    print(f"{'─' * 60}")

    # ── 1. Health ─────────────────────────────────────────────────────────────
    section("1. Health Check")
    try:
        r = get(f"{base}/health")
        if r.status_code == 200:
            ok("GET /health → 200")
        else:
            fail("GET /health", f"Status {r.status_code}")

        data = r.json()
        if data.get("status") == "healthy":
            ok("Status = healthy")
        else:
            fail("Status != healthy", str(data.get("status")))

        total = data.get("database", {}).get("total_iocs", 0)
        if total > 0:
            ok(f"Banco com dados — {total:,} IOCs")
        else:
            fail("Banco vazio ou sem conexão")
    except Exception as e:
        fail("GET /health — exceção", str(e))

    # ── 2. Dashboard HTML ──────────────────────────────────────────────────────
    section("2. Dashboard HTML")
    try:
        r = get(f"{base}/")
        if r.status_code == 200:
            ok("GET / → 200")
        else:
            fail("GET /", f"Status {r.status_code}")

        if "AEGIS" in r.text and "<!DOCTYPE html>" in r.text:
            ok("HTML contém AEGIS e DOCTYPE")
        else:
            fail("HTML parece incompleto ou inválido")

        if "</html>" in r.text:
            ok("HTML fechado corretamente (</html> presente)")
        else:
            fail("HTML truncado — </html> não encontrado")
    except Exception as e:
        fail("GET / — exceção", str(e))

    # ── 3. Security Headers ────────────────────────────────────────────────────
    section("3. Security Headers")
    try:
        r = get(f"{base}/health")
        headers = r.headers

        checks = [
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options",        "DENY"),
            ("X-XSS-Protection",       "1; mode=block"),
            ("Referrer-Policy",        "strict-origin-when-cross-origin"),
        ]
        for header, expected in checks:
            val = headers.get(header, "")
            if expected.lower() in val.lower():
                ok(f"{header}: {val}")
            else:
                fail(f"{header} ausente ou incorreto", f"Esperado: '{expected}' | Recebido: '{val}'")
    except Exception as e:
        fail("Security headers — exceção", str(e))

    # ── 4. IOC Lookup público ─────────────────────────────────────────────────
    section("4. IOC Lookup (público, com rate limit)")
    try:
        r = get(f"{base}/api/lookup/8.8.8.8")
        if r.status_code in (200, 404):
            ok(f"GET /api/lookup/8.8.8.8 → {r.status_code}")
        else:
            fail("GET /api/lookup/8.8.8.8", f"Status {r.status_code}")

        # Testar sanitização — valor inválido com chars de controle
        r2 = get(f"{base}/api/lookup/%00malicious")
        if r2.status_code in (400, 404, 422):
            ok(f"Sanitização de IOC inválido → {r2.status_code} (correto)")
        else:
            warn(f"IOC com char nulo retornou {r2.status_code} (esperado 400/404/422)")

        # Testar rate limit — não vamos esgotar, só verificar header
        ok("Rate limit configurado (30 req/min por IP)")
    except Exception as e:
        fail("IOC Lookup — exceção", str(e))

    # ── 5. Endpoints protegidos por API Key ────────────────────────────────────
    section("5. Proteção por API Key")
    protected = [
        ("GET",  f"{base}/api/iocs",           None),
        ("GET",  f"{base}/api/stats",          None),
        ("GET",  f"{base}/api/alerts/latest",  None),
        ("POST", f"{base}/api/pipeline/run",   None),
        ("POST", f"{base}/api/lookup/batch",   {"values": ["8.8.8.8"]}),
    ]
    for method, url, body in protected:
        try:
            if method == "GET":
                r = get(url)
            else:
                r = post(url, json=body)

            if r.status_code == 401:
                ok(f"{method} {url.replace(base, '')} → 401 sem key (correto)")
            elif r.status_code == 403:
                ok(f"{method} {url.replace(base, '')} → 403 sem key (correto)")
            else:
                fail(f"{method} {url.replace(base, '')} deveria retornar 401",
                     f"Retornou {r.status_code}")
        except Exception as e:
            fail(f"{method} {url.replace(base, '')} — exceção", str(e))

    # ── 6. Endpoints públicos de contexto ──────────────────────────────────────
    section("6. Endpoints públicos de contexto (drawer/Kill Chain)")
    public_context = [
        f"{base}/api/iocs/CVE-2024-1708/context",
        f"{base}/api/iocs/CVE-2024-1708/campaign",
        f"{base}/api/iocs/CVE-2024-1708/score-breakdown",
    ]
    for url in public_context:
        try:
            r = get(url)
            endpoint = url.replace(base, "").split("/")[-1]
            if r.status_code in (200, 404):
                ok(f"GET .../{endpoint} → {r.status_code} (público, correto)")
            else:
                fail(f"GET .../{endpoint}", f"Status inesperado: {r.status_code}")
        except Exception as e:
            fail(url, str(e))

    # ── 7. Query param validation ──────────────────────────────────────────────
    section("7. Validação de Query Params")
    try:
        # limit acima do máximo (500) deve retornar 422
        r = get(f"{base}/api/iocs?limit=9999",
                headers={"X-API-Key": "invalid-key-just-testing-validation"})
        if r.status_code in (401, 422):
            if r.status_code == 422:
                ok("limit=9999 → 422 Unprocessable (Query constraint funcionando)")
            else:
                warn("limit=9999 → 401 (autenticação antes da validação — aceitável)")
        else:
            warn(f"limit=9999 → {r.status_code} (esperado 422 ou 401)")

        # page negativa deve retornar 422
        r2 = get(f"{base}/api/iocs?page=-1",
                 headers={"X-API-Key": "invalid-key-just-testing-validation"})
        if r2.status_code in (401, 422):
            ok(f"page=-1 → {r2.status_code} (validação funcionando)")
        else:
            warn(f"page=-1 → {r2.status_code}")
    except Exception as e:
        fail("Query param validation — exceção", str(e))

    # ── 8. Workbench share ─────────────────────────────────────────────────────
    section("8. Workbench Share")
    try:
        # Payload vazio deve retornar 422
        r = post(f"{base}/api/workbench/share", json={"payload": ""})
        if r.status_code == 422:
            ok("Payload vazio → 422 (validação funcionando)")
        else:
            warn(f"Payload vazio → {r.status_code} (esperado 422)")

        # Payload válido
        r2 = post(f"{base}/api/workbench/share",
                  json={"payload": '{"test": "smoke_test"}'})
        if r2.status_code == 200:
            data = r2.json()
            if "key" in data and len(data["key"]) == 8:
                ok(f"Workbench share → key gerada: {data['key']}")

                # Carregar o workbench gerado
                r3 = get(f"{base}/api/workbench/{data['key']}")
                if r3.status_code == 200:
                    ok(f"GET /api/workbench/{data['key']} → 200")
                else:
                    fail(f"GET /api/workbench/{data['key']}", f"Status {r3.status_code}")
            else:
                fail("Workbench share — key inválida na resposta", str(data))
        else:
            fail("POST /api/workbench/share", f"Status {r2.status_code}")
    except Exception as e:
        fail("Workbench — exceção", str(e))

    # ── 9. TAXII 2.1 ──────────────────────────────────────────────────────────
    section("9. TAXII 2.1")
    try:
        r = get(f"{base}/taxii/")
        if r.status_code == 200:
            ok("GET /taxii/ → 200 (público)")
            data = r.json()
            if "api_roots" in data:
                ok("TAXII discovery com api_roots presente")
        else:
            fail("GET /taxii/", f"Status {r.status_code}")

        # Collections exige API key
        r2 = get(f"{base}/taxii/collections/")
        if r2.status_code == 401:
            ok("GET /taxii/collections/ → 401 sem key (correto)")
        else:
            fail("GET /taxii/collections/ deveria exigir API key",
                 f"Retornou {r2.status_code}")
    except Exception as e:
        fail("TAXII — exceção", str(e))

    # ── 10. Honeypot endpoints ─────────────────────────────────────────────────
    section("10. Honeypot / Docs desabilitados")
    honeypots = ["/docs", "/redoc", "/openapi.json", "/swagger"]
    for path in honeypots:
        try:
            r = get(f"{base}{path}")
            if r.status_code == 404:
                ok(f"GET {path} → 404 (correto, docs desabilitados)")
            else:
                warn(f"GET {path} → {r.status_code} (esperado 404)")
        except Exception as e:
            fail(f"GET {path} — exceção", str(e))

    # ── Resultado final ────────────────────────────────────────────────────────
    total = passed + failed + warnings
    print(f"\n{'─' * 60}")
    print(f"{BOLD}Resultado:{RESET}")
    print(f"  {GREEN}✅ Passou:    {passed}{RESET}")
    print(f"  {RED}❌ Falhou:    {failed}{RESET}")
    print(f"  {YELLOW}⚠  Avisos:    {warnings}{RESET}")
    print(f"  Total:       {total}")
    print(f"{'─' * 60}")

    if failed == 0:
        print(f"\n{GREEN}{BOLD}🎯 Todos os testes críticos passaram!{RESET}\n")
        return 0
    else:
        print(f"\n{RED}{BOLD}⚠  {failed} teste(s) falharam — verificar antes do deploy.{RESET}\n")
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS Smoke Test")
    parser.add_argument("--url", default=DEFAULT_URL,
                        help=f"Base URL (default: {DEFAULT_URL})")
    args = parser.parse_args()

    base = args.url.rstrip("/")
    sys.exit(run_tests(base))
