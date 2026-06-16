import hmac
import os
import subprocess
import sys
import uuid
import sentry_sdk
from fastapi import Depends, FastAPI, BackgroundTasks, HTTPException, Request, Query
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from datetime import datetime, timezone
from pydantic import BaseModel, field_validator
import time

import re
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest

from src.collectors import cisa, otx, mitre
from src.collectors import ip_reputation
from src.processors import normalizer, classifier, deduplicator
from src.processors.classifier import assess_circl_legitimacy
from src.storage.database import DatabaseManager
from src.reporters import html_report
from src.main import run as run_pipeline_task

sentry_dsn = os.getenv("SENTRY_DSN")
if sentry_dsn:
    try:
        sentry_sdk.init(
            dsn=sentry_dsn,
            traces_sample_rate=1.0,
            profiles_sample_rate=0.1,
            environment=os.getenv("DOPPLER_ENVIRONMENT", "production"),
        )
    except Exception:
        pass

_is_production = os.getenv("ENVIRONMENT", "production") == "production"

app = FastAPI(
    title="Aegis Threat Intelligence API",
    version="1.0.0",
    docs_url=None if _is_production else "/docs",
    redoc_url=None if _is_production else "/redoc",
    openapi_url=None if _is_production else "/openapi.json",
)
# ── Security Middleware ───────────────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://aegiscti.me"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["X-API-Key", "Content-Type"],
)

app.mount("/assets", StaticFiles(directory="assets"), name="assets")

# ── Rate limit helpers ────────────────────────────────────────────────────────

_rate_limit: dict = {}          # {client_ip: [timestamp, ...]}
_RATE_LIMIT_MAX = 30
_RATE_LIMIT_WINDOW = 60         # seconds


def _check_rate_limit(client_ip: str) -> bool:
    """Returns True se dentro da quota. Faz cleanup de IPs inativos > 5min."""
    now = time.time()
    if len(_rate_limit) > 10_000:
        stale = [ip for ip, ts in list(_rate_limit.items())
                 if not ts or now - max(ts) > 300]
        for ip in stale:
            del _rate_limit[ip]
    timestamps = [t for t in _rate_limit.get(client_ip, []) if now - t < _RATE_LIMIT_WINDOW]
    if len(timestamps) >= _RATE_LIMIT_MAX:
        _rate_limit[client_ip] = timestamps
        return False
    timestamps.append(now)
    _rate_limit[client_ip] = timestamps
    return True


def _is_ip(value: str) -> bool:
    """Basic IPv4 check: four dot-separated numeric octets in 0–255."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


_MAX_IOC_LEN = 512

def _sanitize_ioc_value(value: str) -> str | None:
    """
    Sanitiza e valida um valor de IOC recebido via path param.
    Remove caracteres de controle e limita tamanho.
    Aceita: IPs, domínios, hashes, CVEs, URLs.
    Retorna None se inválido.
    """
    if not value:
        return None
    value = value.strip()
    if len(value) > _MAX_IOC_LEN:
        return None
    value = re.sub(r'[\x00-\x1f\x7f]', '', value)
    if not value:
        return None
    return value


# ── API Key authentication ────────────────────────────────────────────────────
# Protected:  POST /api/pipeline/run, GET /api/iocs, POST /api/lookup/batch,
#             GET /api/stats, GET /api/stats/trends, GET /api/alerts/latest
# Public:     GET /health, GET /, GET /report, GET /api/lookup/{value}

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _require_api_key(api_key: str | None = Depends(_api_key_header)) -> None:
    configured = os.getenv("AEGIS_API_KEY", "")
    if not configured:
        raise HTTPException(status_code=500, detail="AEGIS_API_KEY not configured on server.")
    # hmac.compare_digest prevents timing attacks
    if not api_key or not hmac.compare_digest(api_key.encode(), configured.encode()):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key. Send it in the X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )


def _require_read_key(api_key: str | None = Depends(_api_key_header)) -> None:
    """Accepts AEGIS_PUBLIC_KEY (dashboard read-only) or AEGIS_API_KEY (admin)."""
    admin_key  = os.getenv("AEGIS_API_KEY", "")
    public_key = os.getenv("AEGIS_PUBLIC_KEY", "")
    if not admin_key:
        raise HTTPException(status_code=500, detail="AEGIS_API_KEY not configured on server.")
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key. Send it in the X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    admin_ok  = hmac.compare_digest(api_key.encode(), admin_key.encode())
    public_ok = bool(public_key) and hmac.compare_digest(api_key.encode(), public_key.encode())
    if not admin_ok and not public_ok:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key. Send it in the X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )


def _inject_public_key(html: str) -> str:
    """Replaces the placeholder comment with a JS variable for the public read-only API key."""
    key    = os.getenv("AEGIS_PUBLIC_KEY", "")
    script = f'<script>window.AEGIS_PUBLIC_KEY = "{key}";</script>'
    return html.replace("<!-- AEGIS_PUBLIC_KEY_PLACEHOLDER -->", script, 1)


# ── Request body schemas ──────────────────────────────────────────────────────

class BatchLookupRequest(BaseModel):
    values: list[str]

    @field_validator("values")
    @classmethod
    def validate_values(cls, v):
        if len(v) > 10:
            raise ValueError("Max 10 values per batch request.")
        sanitized = []
        for val in v:
            val = str(val).strip()[:500]
            if val:
                sanitized.append(val)
        return sanitized


class FalsePositiveBody(BaseModel):
    note: str = ""
    api_key: str

    @field_validator("note")
    @classmethod
    def sanitize_note(cls, v):
        v = str(v).strip()[:1000]
        v = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', v)
        return v

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, v):
        if not v or not str(v).strip():
            raise ValueError("api_key é obrigatória.")
        return str(v).strip()[:256]


class RevertFalsePositiveBody(BaseModel):
    api_key: str

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, v):
        if not v or not str(v).strip():
            raise ValueError("api_key é obrigatória.")
        return str(v).strip()[:256]


class ShareWorkbenchRequest(BaseModel):
    payload: str

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, v):
        v = str(v).strip()
        if not v:
            raise ValueError("payload não pode ser vazio.")
        if len(v) > 50_000:
            raise ValueError("Payload muito grande (max 50kb).")
        return v


# ── Existing endpoints ────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    """
    Returns detailed health status of the AEGIS platform.
    Used by Railway for uptime monitoring and by operators
    for quick system diagnostics.
    """
    health = {
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": {
            "status": "unknown",
            "total_iocs": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "last_updated": None,
        },
        "pipeline": {
            "sources": [
                "CISA-KEV",
                "AlienVault-OTX",
                "ThreatFox",
                "URLhaus",
                "FeodoTracker",
                "DShield",
                "EmergingThreats",
                "GreyNoise",
                "IPsum",
                "Spamhaus-DROP",
            ],
        },
    }

    db = DatabaseManager()
    try:
        stats = db.get_stats()
        by_severity = stats.get("by_severity", {})

        health["database"]["status"] = "connected"
        health["database"]["total_iocs"] = sum(by_severity.values())
        health["database"]["critical"] = by_severity.get("CRITICAL", 0)
        health["database"]["high"] = by_severity.get("HIGH", 0)
        health["database"]["medium"] = by_severity.get("MEDIUM", 0)
        health["database"]["low"] = by_severity.get("LOW", 0)

        last_ioc = db.get_last_updated()
        if last_ioc:
            health["database"]["last_updated"] = last_ioc

        health["decay_stats"] = db.get_decay_stats()

    except Exception as e:
        health["status"] = "degraded"
        health["database"]["status"] = "error"
        health["database"]["error"] = str(e)
    finally:
        db.close()

    return health


@app.get("/api/iocs", dependencies=[Depends(_require_read_key)])
async def get_all_iocs(
    page: int = Query(default=1, ge=1, le=10000),
    limit: int = Query(default=50, ge=1, le=500),
    severity: str | None = Query(default=None, max_length=20),
    type: str | None = Query(default=None, max_length=20),
    search: str | None = Query(default=None, max_length=200),
    status: str | None = Query(default=None, max_length=20),
    keywords: str | None = Query(default=None, max_length=500),
):
    db = DatabaseManager()
    kw_list = [k.strip() for k in keywords.split(",") if k.strip()] if keywords else None
    try:
        return db.get_iocs_paginated(
            page=page, limit=limit, severity=severity, ioc_type=type,
            search=search, status=status, keywords_list=kw_list,
        )
    finally:
        db.close()


@app.get("/api/stats", dependencies=[Depends(_require_api_key)])
async def get_stats():
    db = DatabaseManager()
    try:
        stats = db.get_stats()
        return stats
    finally:
        db.close()


@app.get("/api/stats/trends", dependencies=[Depends(_require_api_key)])
async def get_trends(days: int = Query(default=30, ge=1, le=90)):
    """
    Returns IOC counts grouped by day for the last N days.
    Useful for trend charts and activity monitoring.
    Max 90 days.
    """
    db = DatabaseManager()
    try:
        trends = db.get_trends(days)
        return {
            "days": days,
            "data_points": len(trends),
            "trends": trends,
        }
    finally:
        db.close()


@app.get("/api/overview", dependencies=[Depends(_require_read_key)])
async def get_overview():
    """
    Panorama operacional do SOC: distribuições por severidade/tipo/status,
    rankings de infraestrutura atacante (ASN, país, fonte), táticas MITRE,
    atores e campanhas, e a timeline de 30 dias. Tudo agregado no banco.
    Usado pela aba **Threat Overview** do dashboard.
    """
    db = DatabaseManager()
    try:
        return db.get_overview()
    finally:
        db.close()


@app.get("/api/graph", dependencies=[Depends(_require_read_key)])
async def get_graph(
    campaign_id: str | None = Query(default=None, max_length=64),
    asn: int | None = Query(default=None, ge=0, le=4_294_967_295),
    tactic: str | None = Query(default=None, max_length=64),
    country: str | None = Query(default=None, max_length=8),
    adversary: str | None = Query(default=None, max_length=128),
    seed: str | None = Query(default=None, max_length=512),
    limit: int = Query(default=120, ge=10, le=250),
):
    """
    Grafo de correlação (nós = IOCs, arestas = infraestrutura comum do atacante:
    campanha compartilhada, mesmo ASN, mesmo /24). Sem filtros, retorna os
    clusters das maiores campanhas. Usado pela aba **Correlation Graph**.
    """
    if seed:
        seed = _sanitize_ioc_value(seed)
    db = DatabaseManager()
    try:
        return db.get_correlation_graph(
            campaign_id=campaign_id, asn=asn, tactic=tactic,
            country=country, adversary=adversary, seed=seed, limit=limit,
        )
    finally:
        db.close()


# Handle do processo-filho do pipeline. Com WEB_CONCURRENCY=1 (1 worker uvicorn)
# este estado de módulo é confiável; mesmo com mais workers, o guard de
# idempotência server-side (PIPELINE_MIN_INTERVAL_MIN em src/main.py) é a rede de
# proteção real contra runs duplicados.
_pipeline_proc: subprocess.Popen | None = None


@app.post("/api/pipeline/run", dependencies=[Depends(_require_api_key)])
async def run_pipeline():
    global _pipeline_proc

    # Reapa o run anterior se já terminou (evita zumbi) e barra disparo concorrente.
    if _pipeline_proc is not None and _pipeline_proc.poll() is None:
        return {
            "status": "already_running",
            "message": "O pipeline já está em execução. Aguarde a conclusão.",
        }

    # Roda o pipeline em PROCESSO SEPARADO (mesmo container, env, FS e Postgres) em
    # vez de uma thread dentro do uvicorn. Isolamento de memória: se o pipeline
    # estourar a RAM (512MB no Render), o kernel mata ESTE filho — o web server
    # (uvicorn) continua de pé respondendo /health e /report. start_new_session
    # desacopla o filho do ciclo de vida do worker web.
    project_root = Path(__file__).resolve().parents[1]
    _pipeline_proc = subprocess.Popen(
        [sys.executable, "-m", "src.main"],
        cwd=str(project_root),
        start_new_session=True,
    )
    return {
        "status": "processing",
        "message": "O pipeline de inteligência foi iniciado em segundo plano! Demora alguns minutos. Aguarde e recarregue a página inicial daqui a pouco para ver o painel gerado."
    }


@app.get("/report")
async def get_report():
    db = DatabaseManager()
    try:
        html = db.get_latest_report()
    finally:
        db.close()
    if html:
        return HTMLResponse(content=_inject_public_key(html))
    report_path = Path(__file__).resolve().parents[1] / "output" / "index.html"
    if report_path.exists():
        html = report_path.read_text(encoding="utf-8")
        return HTMLResponse(content=_inject_public_key(html))
    return {"error": "Report not generated yet. Run /api/pipeline/run first"}


@app.post("/api/admin/force-report", dependencies=[Depends(_require_api_key)])
async def force_report(background_tasks: BackgroundTasks):
    from src.storage.database import DatabaseManager
    from src.reporters import html_report
    from src.collectors import mitre

    async def _regen():
        db = DatabaseManager()
        try:
            # Mesmo padrão do pipeline (main.py fase 2): relatório a partir de partes
            # paginadas, sem get_all_iocs() (SELECT * FROM iocs estourava a RAM ao
            # carregar a tabela inteira, agora mais pesada com as colunas de pDNS/pSSL).
            stats = db.get_stats()
            trends = db.get_trends(days=30)
            techniques = mitre.load_techniques()
            top_iocs = db.get_iocs_paginated(page=1, limit=1000)["iocs"]
            html_report.generate_from_parts(top_iocs, stats, techniques, trends, db.get_total_count())
            print("[force-report] done")
        finally:
            db.close()

    background_tasks.add_task(_regen)
    return {"status": "regenerating"}


@app.get("/")
async def root():
    db = DatabaseManager()
    try:
        html = db.get_latest_report()
    finally:
        db.close()
    if html:
        return HTMLResponse(content=_inject_public_key(html))

    report_path = Path(__file__).resolve().parents[1] / "output" / "index.html"
    if report_path.exists():
        html = report_path.read_text(encoding="utf-8")
        return HTMLResponse(content=_inject_public_key(html))

    html_content = """
    <html>
        <head>
            <title>Aegis Threat Intelligence</title>
            <style>
                body { font-family: sans-serif; text-align: center; margin-top: 50px; background: #111; color: #fff; }
                a { color: #00ffcc; text-decoration: none; font-weight: bold; padding: 10px 20px; border: 1px solid #00ffcc; border-radius: 5px; display: inline-block; margin-top: 20px;}
                a:hover { background: #00ffcc; color: #111; }
                .card { background: #222; padding: 40px; border-radius: 8px; display: inline-block; border: 1px solid #333; max-width: 500px; line-height: 1.6; }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>Aegis Threat Intelligence</h1>
                <p>O painel visual ainda não possui dados porque o banco está vazio neste servidor.</p>
                <p>Para gerar o relatório HTML, você precisa executar o <b>pipeline de coleta de ameaças</b> através do painel interativo da API.</p>
                <a href="/report">Ver Relatório de Ameaças</a>
            </div>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content)


# ── Security: honeypot endpoints to mislead automated scanners ────────────────

@app.get("/api/docs-disabled")
@app.get("/swagger")
@app.get("/swagger-ui")
async def docs_honeypot():
    raise HTTPException(status_code=404, detail="Not Found")


# ── New endpoints ─────────────────────────────────────────────────────────────

@app.get("/api/lookup/{value}")
async def lookup_ioc(value: str, request: Request):
    """
    Look up a single IOC by exact value (IP, domain, hash, or CVE).

    - If found in the database and the type is **ip**, live GreyNoise Community
      reputation data is merged into the response (cached per IP for 1 hour).
    - If **not** found but the value is a valid IPv4 address, returns live
      GreyNoise data with `found_in_db: false`.
    - Returns 404 when not found and the value is not a valid IP.

    Rate limited to **30 requests per minute** per client IP (HTTP 429 on excess).
    """
    client_ip = request.client.host
    if not _check_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Max 30 lookups per minute.",
        )

    value = _sanitize_ioc_value(value)
    if not value:
        raise HTTPException(status_code=400, detail="Valor de IOC inválido.")

    db = DatabaseManager()
    try:
        record = db.get_ioc_by_value(value)
    finally:
        db.close()

    # Found in database
    if record is not None:
        result = dict(record)
        result["found_in_db"] = True

        if record.get("type") == "ip":
            live = ip_reputation.lookup_ip(record["value"])
            from_cache = live.pop("_from_cache", False)
            result["live_abuse_score"] = live.get("abuse_score")
            result["live_country"]     = live.get("country")
            result["isp"]              = live.get("isp")
            result["total_reports"]    = live.get("total_reports")
            result["last_reported"]    = live.get("last_reported")
            result["usage_type"]       = live.get("usage_type")
            result["live_data_cached"] = from_cache
            result["abuse_categories"] = live.get("abuse_categories")

        return result

    # Not in database — fall back to live GreyNoise reputation for valid IPs
    if _is_ip(value):
        live = ip_reputation.lookup_ip(value)
        from_cache = live.pop("_from_cache", False)
        live["found_in_db"]      = False
        live["live_data_cached"] = from_cache
        live["message"]          = "Not in local database — showing live GreyNoise reputation data only"
        return live

    raise HTTPException(status_code=404, detail=f"IOC '{value}' not found in database.")


@app.get("/api/alerts/latest", dependencies=[Depends(_require_api_key)])
async def get_latest_alerts(hours: int = Query(default=24, ge=1, le=168)):
    """
    Returns the most recent **CRITICAL** IOCs added within the last N hours.

    - `hours` query parameter: 1–168 (default 24, capped at 168 = 7 days).
    - Results sorted by `first_seen` descending; capped at 100 entries.
    - **No rate limiting** — intended for automated SIEM, Slack, and Teams integrations.
    """

    db = DatabaseManager()
    try:
        alerts = db.get_critical_since(hours=hours, limit=100)
    finally:
        db.close()

    return {
        "period_hours": hours,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_critical": len(alerts),
        "alerts": alerts,
    }


@app.post("/api/lookup/batch", dependencies=[Depends(_require_api_key)])
async def lookup_batch(body: BatchLookupRequest):
    """
    Look up up to **10 IOC values** at once against the local database.

    - Accepts a JSON body: `{"values": ["value1", "value2", ...]}`
    - Live GreyNoise reputation is **not** called for batch requests (rate limit protection).
    - Returns HTTP 400 if more than 10 values are submitted.
    - Always returns HTTP 200; each result includes a `found_in_db` flag.
    """
    if len(body.values) > 10:
        raise HTTPException(
            status_code=400,
            detail="Max 10 values per batch request.",
        )

    db = DatabaseManager()
    try:
        results = []
        for value in body.values:
            record = db.get_ioc_by_value(value)
            if record is not None:
                item = dict(record)
                item["found_in_db"] = True
            else:
                item = {"value": value, "found_in_db": False}
            results.append(item)
    finally:
        db.close()

    return {"total": len(results), "results": results}


# ── BioSec Contextualisation endpoints ───────────────────────────────────────


@app.get("/api/iocs/{value}/score-breakdown")
async def get_score_breakdown(value: str):
    """Returns the detailed score breakdown for a single IOC. Public — no API key required."""
    value = _sanitize_ioc_value(value)
    if not value:
        raise HTTPException(status_code=400, detail="Valor de IOC inválido.")
    db = DatabaseManager()
    try:
        ioc = db.get_ioc_context(value)
    finally:
        db.close()
    if not ioc:
        raise HTTPException(status_code=404, detail=f"IOC '{value}' não encontrado.")
    breakdown = ioc.get("score_breakdown")
    if not breakdown:
        return {
            "value": value,
            "score_breakdown": None,
            "message": "Execute o pipeline para calcular o score detalhado.",
        }
    return {"value": value, "score_breakdown": breakdown}


def _circl_groups(ioc: dict) -> None:
    """Monta os grupos circl_pdns/circl_pssl no dict do IOC (in-place), apenas se
    houver dados de enriquecimento (campos não-None). Mantém a rota retrocompatível:
    IOCs sem CIRCL simplesmente não ganham os grupos."""
    if ioc.get("pdns_record_count") is not None:
        ioc["circl_pdns"] = {
            "record_count":       ioc.get("pdns_record_count"),
            "first_seen":         ioc.get("pdns_first_seen"),
            "last_seen":          ioc.get("pdns_last_seen"),
            "resolutions":        ioc.get("pdns_resolutions"),
            "associated_ips":     ioc.get("pdns_associated_ips"),
            "associated_domains": ioc.get("pdns_associated_domains"),
            "suspicious":         bool(ioc.get("pdns_suspicious")),
            "enriched_at":        ioc.get("pdns_enriched_at"),
        }
    if ioc.get("pssl_cert_count") is not None:
        ioc["circl_pssl"] = {
            "cert_count":   ioc.get("pssl_cert_count"),
            "certificates": ioc.get("pssl_certificates"),
            "subjects":     ioc.get("pssl_subjects"),
            "self_signed":  bool(ioc.get("pssl_self_signed")),
            "expired":      bool(ioc.get("pssl_expired")),
            "suspicious":   bool(ioc.get("pssl_suspicious")),
            "enriched_at":  ioc.get("pssl_enriched_at"),
        }
    # Veredito de legitimidade da infraestrutura (contexto, NÃO altera o score).
    assessment = assess_circl_legitimacy(ioc)
    if assessment:
        ioc["circl_assessment"] = assessment


@app.get("/api/iocs/{value}/context")
async def get_ioc_context(value: str):
    """Returns full IOC context plus correlated IOCs from the same source.
    Public — no API key required. Used by the drawer panel."""
    value = _sanitize_ioc_value(value)
    if not value:
        raise HTTPException(status_code=400, detail="Valor de IOC inválido.")
    db = DatabaseManager()
    try:
        ioc = db.get_ioc_context(value)
        if not ioc:
            raise HTTPException(status_code=404, detail=f"IOC '{value}' não encontrado.")
        _circl_groups(ioc)
        correlated = db.get_correlated_iocs(
            source=ioc.get("source", ""),
            exclude_value=value,
            limit=5,
        )
        return {"ioc": ioc, "correlated_iocs": correlated}
    finally:
        db.close()


@app.get("/api/iocs/{value}/campaign")
async def get_ioc_campaign(value: str):
    """
    Retorna contexto de campanha para um IOC — Kill Chain reconstruída
    e IOCs similares correlacionados por tipo. Público.
    """
    value = _sanitize_ioc_value(value)
    if not value:
        raise HTTPException(status_code=400, detail="Valor de IOC inválido.")
    db = DatabaseManager()
    try:
        ioc = db.get_ioc_context(value)
        if not ioc:
            raise HTTPException(status_code=404, detail=f"IOC '{value}' não encontrado.")
        campaign = db.get_campaign_context(
            value=value,
            ioc_type=ioc.get("type", ""),
            ioc_data=ioc,
        )
        campaign["ioc"] = ioc
        return campaign
    finally:
        db.close()


@app.post("/api/iocs/{value}/false-positive")
async def mark_false_positive_endpoint(value: str, body: FalsePositiveBody):
    """Marks an IOC as a false positive. Requires AEGIS_API_KEY in the request body."""
    configured = os.getenv("AEGIS_API_KEY", "")
    if not configured:
        raise HTTPException(status_code=500, detail="AEGIS_API_KEY não configurada no servidor.")
    if not body.api_key or not hmac.compare_digest(body.api_key.encode(), configured.encode()):
        raise HTTPException(status_code=401, detail="API key inválida.")
    value = _sanitize_ioc_value(value)
    if not value:
        raise HTTPException(status_code=400, detail="Valor de IOC inválido.")
    db = DatabaseManager()
    try:
        ok = db.mark_false_positive(value, body.note)
    finally:
        db.close()
    if not ok:
        raise HTTPException(status_code=404, detail=f"IOC '{value}' não encontrado.")
    return {"success": True, "message": "IOC marcado como falso positivo."}


@app.post("/api/iocs/{value}/revert-false-positive")
async def revert_false_positive_endpoint(value: str, body: RevertFalsePositiveBody):
    """Reverts a false-positive flag. Requires AEGIS_API_KEY in the request body."""
    configured = os.getenv("AEGIS_API_KEY", "")
    if not configured:
        raise HTTPException(status_code=500, detail="AEGIS_API_KEY não configurada no servidor.")
    if not body.api_key or not hmac.compare_digest(body.api_key.encode(), configured.encode()):
        raise HTTPException(status_code=401, detail="API key inválida.")
    value = _sanitize_ioc_value(value)
    if not value:
        raise HTTPException(status_code=400, detail="Valor de IOC inválido.")
    db = DatabaseManager()
    try:
        ok = db.unmark_false_positive(value)
    finally:
        db.close()
    if not ok:
        raise HTTPException(status_code=404, detail=f"IOC '{value}' não encontrado.")
    return {"success": True, "message": "Falso positivo revertido."}


# ── Analyst Workbench ─────────────────────────────────────────────────────────

@app.post("/api/workbench/share")
async def share_workbench(body: ShareWorkbenchRequest):
    """
    Recebe o workbench serializado do frontend e salva no banco com
    chave aleatória de 8 caracteres. Expira em 24 horas.
    Público — o código aleatório é a autenticação.
    """
    import secrets
    from datetime import timezone, timedelta

    if len(body.payload) > 50_000:
        raise HTTPException(status_code=400, detail="Payload muito grande (max 50kb).")

    key = secrets.token_urlsafe(6)[:8].upper()
    expires_at = (datetime.utcnow() + timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")

    db = DatabaseManager()
    try:
        db.save_shared_workbench(key, body.payload, expires_at)
    finally:
        db.close()

    return {"key": key, "expires_at": expires_at}


@app.get("/api/workbench/{key}")
async def get_workbench(key: str):
    """
    Retorna workbench compartilhado por chave.
    404 se não existir ou expirado.
    """
    db = DatabaseManager()
    try:
        wb = db.get_shared_workbench(key.upper())
    finally:
        db.close()

    if not wb:
        raise HTTPException(
            status_code=404,
            detail="Workbench não encontrado ou expirado (validade: 24h)."
        )
    return wb


# ── TAXII 2.1 ─────────────────────────────────────────────────────────────────
# Discovery:   GET /taxii/                                    — public
# Collections: GET /taxii/collections/                        — requires API Key
# Objects:     GET /taxii/collections/{collection_id}/objects/ — requires API Key

_TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"

_TAXII_COLLECTIONS = {
    "all": {
        "id": "all",
        "title": "All IOCs",
        "description": "All threat indicators regardless of severity",
        "can_read": True,
        "can_write": False,
        "media_types": [_TAXII_MEDIA_TYPE],
    },
    "critical": {
        "id": "critical",
        "title": "Critical IOCs",
        "description": "Critical severity threat indicators",
        "can_read": True,
        "can_write": False,
        "media_types": [_TAXII_MEDIA_TYPE],
    },
    "high": {
        "id": "high",
        "title": "High IOCs",
        "description": "High severity threat indicators",
        "can_read": True,
        "can_write": False,
        "media_types": [_TAXII_MEDIA_TYPE],
    },
    "medium": {
        "id": "medium",
        "title": "Medium IOCs",
        "description": "Medium severity threat indicators",
        "can_read": True,
        "can_write": False,
        "media_types": [_TAXII_MEDIA_TYPE],
    },
}

def _hash_stix_pattern(v: str) -> str:
    """STIX 2.1 hash pattern com o algoritmo CORRETO inferido pelo comprimento hex.

    Antes todo hash virava `file:hashes.MD5`, marcando SHA-1/SHA-256/SHA-512 como
    MD5 — padrão inválido para o consumidor TAXII. Chaves com hífen exigem aspas
    no padrão STIX (`file:hashes.'SHA-256'`); MD5 não. Fallback para MD5 em
    comprimentos não reconhecidos (preserva o comportamento antigo)."""
    h = (v or "").strip()
    algo = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}.get(len(h), "MD5")
    key = "MD5" if algo == "MD5" else f"'{algo}'"
    return f"[file:hashes.{key} = '{h}']"


_STIX_PATTERNS: dict = {
    "ip":     lambda v: f"[ipv4-addr:value = '{v}']",
    "domain": lambda v: f"[domain-name:value = '{v}']",
    "url":    lambda v: f"[url:value = '{v}']",
    "hash":   _hash_stix_pattern,
    "cve":    lambda v: f"[vulnerability:name = '{v}']",
}


def _to_stix_timestamp(ts: str | None) -> str:
    """Normalise a possibly-bare date/datetime string to RFC 3339 with Z suffix."""
    if not ts:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ts = str(ts).strip()
    if "T" not in ts:
        return ts[:10] + "T00:00:00Z"
    if not ts.endswith("Z") and "+" not in ts:
        return ts[:19] + "Z"
    return ts


def _ioc_to_stix(ioc: dict) -> dict:
    ioc_type  = (ioc.get("type") or "").lower()
    value     = ioc.get("value", "")
    severity  = (ioc.get("severity") or "unknown").lower()
    source    = (ioc.get("source") or "aegis").lower()
    timestamp = _to_stix_timestamp(ioc.get("first_seen"))
    tactic    = ioc.get("mitre_tactic")

    pattern_fn = _STIX_PATTERNS.get(ioc_type, lambda v: f"[x-unknown:value = '{v}']")

    # uuid5 with NAMESPACE_DNS → deterministic: same IOC value always yields the same STIX ID
    stix_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, value)}"

    obj: dict = {
        "type":         "indicator",
        "spec_version": "2.1",
        "id":           stix_id,
        "created":      timestamp,
        "modified":     timestamp,
        "name":         value,
        "pattern":      pattern_fn(value),
        "pattern_type": "stix",
        "valid_from":   timestamp,
        "labels":       [severity, source],
    }

    if tactic:
        obj["kill_chain_phases"] = [
            {"kill_chain_name": "mitre-attack", "phase_name": tactic.lower()}
        ]

    return obj


@app.get("/taxii/")
async def taxii_discovery():
    return JSONResponse(
        content={
            "title":       "Aegis Threat Intelligence TAXII Server",
            "description": "TAXII 2.1 feed exposing STIX 2.1 Indicator objects",
            "contact":     "aegis-threat-intel",
            "default":     "/taxii/",
            "api_roots":   ["/taxii/"],
        },
        media_type=_TAXII_MEDIA_TYPE,
    )


@app.get("/taxii/collections/", dependencies=[Depends(_require_api_key)])
async def taxii_collections():
    return JSONResponse(
        content={"collections": list(_TAXII_COLLECTIONS.values())},
        media_type=_TAXII_MEDIA_TYPE,
    )


@app.get("/taxii/collections/{collection_id}/objects/", dependencies=[Depends(_require_api_key)])
async def taxii_collection_objects(collection_id: str, limit: int = 100):
    if collection_id not in _TAXII_COLLECTIONS:
        raise HTTPException(
            status_code=404,
            detail=f"Collection '{collection_id}' not found. Valid: {list(_TAXII_COLLECTIONS)}",
        )

    limit = min(limit, 500)

    db = DatabaseManager()
    try:
        # Consulta com LIMIT no banco — NUNCA carrega a tabela inteira (SELECT *
        # FROM iocs sem limite estourava a RAM no Render 512MB, agravado pelas
        # colunas grandes de pDNS/pSSL). `raw` já vem com no máximo `limit` linhas.
        severity = None if collection_id == "all" else collection_id.upper()
        raw = db.get_iocs_paginated(page=1, limit=limit, severity=severity)["iocs"]
    finally:
        db.close()

    bundle_id = f"bundle--{uuid.uuid5(uuid.NAMESPACE_DNS, f'aegis-{collection_id}')}"

    return JSONResponse(
        content={
            "type":    "bundle",
            "id":      bundle_id,
            "objects": [_ioc_to_stix(ioc) for ioc in raw[:limit]],
        },
        media_type=_TAXII_MEDIA_TYPE,
    )
