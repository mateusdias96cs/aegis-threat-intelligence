import hmac
import os
import uuid
import sentry_sdk
from fastapi import Depends, FastAPI, BackgroundTasks, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from datetime import datetime, timezone
from pydantic import BaseModel
import time

from src.collectors import cisa, otx, mitre
from src.collectors import abuseipdb
from src.processors import normalizer, classifier, deduplicator
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
app.mount("/assets", StaticFiles(directory="assets"), name="assets")

# ── Rate limit helpers ────────────────────────────────────────────────────────

_rate_limit: dict = {}          # {client_ip: [timestamp, ...]}
_RATE_LIMIT_MAX = 30
_RATE_LIMIT_WINDOW = 60         # seconds


def _check_rate_limit(client_ip: str) -> bool:
    """Returns True if the request is within quota, False if limit is exceeded."""
    now = time.time()
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


# ── Request body schemas ──────────────────────────────────────────────────────

class BatchLookupRequest(BaseModel):
    values: list[str]


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
                "AbuseIPDB-Blacklist",
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

    except Exception as e:
        health["status"] = "degraded"
        health["database"]["status"] = "error"
        health["database"]["error"] = str(e)
    finally:
        db.close()

    return health


@app.get("/api/iocs", dependencies=[Depends(_require_api_key)])
async def get_all_iocs():
    db = DatabaseManager()
    try:
        iocs = db.get_all_iocs()
        return {"total": len(iocs), "iocs": iocs}
    finally:
        db.close()


@app.get("/api/iocs/severity/{severity}")
async def get_iocs_by_severity(severity: str):
    db = DatabaseManager()
    try:
        iocs = db.get_iocs_by_severity(severity.upper())
        return {"severity": severity, "count": len(iocs), "iocs": iocs}
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
async def get_trends(days: int = 30):
    """
    Returns IOC counts grouped by day for the last N days.
    Useful for trend charts and activity monitoring.
    Max 90 days.
    """
    days = min(days, 90)
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


@app.post("/api/pipeline/run", dependencies=[Depends(_require_api_key)])
async def run_pipeline(background_tasks: BackgroundTasks):
    background_tasks.add_task(run_pipeline_task)
    return {
        "status": "processing",
        "message": "O pipeline de inteligência foi iniciado em segundo plano! Demora alguns minutos. Aguarde e recarregue a página inicial daqui a pouco para ver o painel gerado."
    }


@app.get("/report")
async def get_report():
    report_path = Path(__file__).resolve().parents[1] / "output" / "index.html"
    if report_path.exists():
        return FileResponse(report_path, media_type="text/html")
    db = DatabaseManager()
    try:
        html = db.get_latest_report()
    finally:
        db.close()
    if html:
        return HTMLResponse(content=html)
    return {"error": "Report not generated yet. Run /api/pipeline/run first"}


@app.get("/")
async def root():
    report_path = Path(__file__).resolve().parents[1] / "output" / "index.html"
    if report_path.exists():
        return FileResponse(report_path, media_type="text/html")

    db = DatabaseManager()
    try:
        html = db.get_latest_report()
    finally:
        db.close()
    if html:
        return HTMLResponse(content=html)

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

    - If found in the database and the type is **ip**, live AbuseIPDB enrichment
      data is merged into the response (cached per IP for 1 hour).
    - If **not** found but the value is a valid IPv4 address, returns live
      AbuseIPDB data with `found_in_db: false`.
    - Returns 404 when not found and the value is not a valid IP.

    Rate limited to **30 requests per minute** per client IP (HTTP 429 on excess).
    """
    client_ip = request.client.host
    if not _check_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Max 30 lookups per minute.",
        )

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
            live = abuseipdb.lookup_ip(record["value"])
            from_cache = live.pop("_from_cache", False)
            result["live_abuse_score"] = live.get("abuse_score")
            result["live_country"]     = live.get("country")
            result["isp"]              = live.get("isp")
            result["total_reports"]    = live.get("total_reports")
            result["last_reported"]    = live.get("last_reported")
            result["usage_type"]       = live.get("usage_type")
            result["live_data_cached"] = from_cache

        return result

    # Not in database — fall back to live AbuseIPDB for valid IPs
    if _is_ip(value):
        live = abuseipdb.lookup_ip(value)
        from_cache = live.pop("_from_cache", False)
        live["found_in_db"]      = False
        live["live_data_cached"] = from_cache
        live["message"]          = "Not in local database — showing live AbuseIPDB data only"
        return live

    raise HTTPException(status_code=404, detail=f"IOC '{value}' not found in database.")


@app.get("/api/alerts/latest", dependencies=[Depends(_require_api_key)])
async def get_latest_alerts(hours: int = 24):
    """
    Returns the most recent **CRITICAL** IOCs added within the last N hours.

    - `hours` query parameter: 1–168 (default 24, capped at 168 = 7 days).
    - Results sorted by `first_seen` descending; capped at 100 entries.
    - **No rate limiting** — intended for automated SIEM, Slack, and Teams integrations.
    """
    hours = min(max(hours, 1), 168)

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
    - AbuseIPDB is **not** called for batch requests (rate limit protection).
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

_STIX_PATTERNS: dict = {
    "ip":     lambda v: f"[ipv4-addr:value = '{v}']",
    "domain": lambda v: f"[domain-name:value = '{v}']",
    "url":    lambda v: f"[url:value = '{v}']",
    "hash":   lambda v: f"[file:hashes.MD5 = '{v}']",
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
        raw = db.get_all_iocs() if collection_id == "all" else db.get_iocs_by_severity(collection_id.upper())
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
