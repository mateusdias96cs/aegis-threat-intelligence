import os
import sentry_sdk
from fastapi import FastAPI, BackgroundTasks, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
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
            traces_sample_rate=0.1,
            profiles_sample_rate=0.1,
            environment=os.getenv("DOPPLER_ENVIRONMENT", "production"),
        )
    except Exception:
        pass

app = FastAPI(title="Aegis Threat Intelligence API", version="1.0.0")
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


@app.get("/api/iocs")
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


@app.get("/api/stats")
async def get_stats():
    db = DatabaseManager()
    try:
        stats = db.get_stats()
        return stats
    finally:
        db.close()


@app.get("/api/stats/trends")
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


@app.post("/api/pipeline/run")
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
    return {"error": "Report not generated yet. Run /api/pipeline/run first"}


@app.get("/")
async def root():
    report_path = Path(__file__).resolve().parents[1] / "output" / "index.html"
    if report_path.exists():
        return FileResponse(report_path, media_type="text/html")

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
                <a href="/docs">Acessar Painel da API (/docs)</a>
            </div>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content)


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


@app.get("/api/alerts/latest")
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


@app.post("/api/lookup/batch")
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
