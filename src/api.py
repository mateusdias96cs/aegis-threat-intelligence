from fastapi import FastAPI
from fastapi.responses import FileResponse
from pathlib import Path

from src.collectors import cisa, otx, mitre
from src.collectors import abuseipdb
from src.processors import normalizer, classifier, deduplicator
from src.storage.database import DatabaseManager
from src.reporters import html_report

app = FastAPI(title="Aegis Threat Intelligence API", version="1.0.0")

# Rota de health check (para Railway saber que está funcionando)
@app.get("/health")
async def health_check():
    return {"status": "ok", "message": "API is running"}

# Rota para obter todos os IOCs
@app.get("/api/iocs")
async def get_all_iocs():
    db = DatabaseManager()
    try:
        iocs = db.get_all_iocs()
        return {"total": len(iocs), "iocs": iocs}
    finally:
        db.close()

# Rota para obter IOCs por severidade
@app.get("/api/iocs/severity/{severity}")
async def get_iocs_by_severity(severity: str):
    db = DatabaseManager()
    try:
        iocs = db.get_iocs_by_severity(severity.upper())
        return {"severity": severity, "count": len(iocs), "iocs": iocs}
    finally:
        db.close()

# Rota para obter estatísticas
@app.get("/api/stats")
async def get_stats():
    db = DatabaseManager()
    try:
        stats = db.get_stats()
        return stats
    finally:
        db.close()

# Rota para executar o pipeline manualmente
@app.post("/api/pipeline/run")
async def run_pipeline():
    try:
        # Collect
        print("[pipeline] collecting from CISA-KEV ...")
        cisa_iocs = cisa.collect()
        print(f"[pipeline] CISA-KEV: {len(cisa_iocs)} indicators")

        print("[pipeline] collecting from AlienVault OTX ...")
        otx_iocs = otx.collect()
        print(f"[pipeline] OTX: {len(otx_iocs)} indicators")

        raw_iocs = cisa_iocs + otx_iocs
        print(f"[pipeline] total collected: {len(raw_iocs)}")

        # Load MITRE ATT&CK technique index
        print("[pipeline] loading MITRE ATT&CK techniques ...")
        techniques = mitre.load_techniques()
        print(f"[pipeline] MITRE: {len(techniques)} techniques loaded")

        # Process
        print("[pipeline] normalizing ...")
        iocs = normalizer.normalize(raw_iocs)

        print("[pipeline] enriching IPs via AbuseIPDB ...")
        iocs = abuseipdb.enrich_batch(iocs)

        print("[pipeline] classifying ...")
        iocs = classifier.classify(iocs)

        print("[pipeline] mapping to MITRE ATT&CK ...")
        for ioc in iocs:
            technique = mitre.map_ioc_to_technique(ioc, techniques)
            if technique:
                ioc["mitre_technique_id"] = technique["id"]
                ioc["mitre_tactic"] = technique["tactic"]
            else:
                ioc["mitre_technique_id"] = None
                ioc["mitre_tactic"] = None

        print("[pipeline] deduplicating ...")
        iocs = deduplicator.deduplicate(iocs)
        print(f"[pipeline] after deduplication: {len(iocs)}")

        # Persist
        print("[pipeline] saving to database ...")
        db = DatabaseManager()
        try:
            db.insert_many(iocs)
            stats = db.get_stats()
            all_iocs = db.get_all_iocs()
            html_report.generate(all_iocs, stats, techniques)
            
            return {
                "status": "success",
                "total_collected": len(raw_iocs),
                "after_deduplication": len(iocs),
                "stats": stats
            }
        finally:
            db.close()
    except Exception as e:
        return {"status": "error", "message": str(e)}

# Servir o relatório HTML
@app.get("/report")
async def get_report():
    report_path = Path(__file__).resolve().parents[1] / "output" / "index.html"
    if report_path.exists():
        return FileResponse(report_path, media_type="text/html")
    return {"error": "Report not generated yet. Run /api/pipeline/run first"}

# Página inicial
@app.get("/")
async def root():
    return {
        "message": "Aegis Threat Intelligence API",
        "endpoints": {
            "health": "/health",
            "get_all_iocs": "/api/iocs",
            "get_iocs_by_severity": "/api/iocs/severity/{severity}",
            "get_stats": "/api/stats",
            "run_pipeline": "POST /api/pipeline/run",
            "get_report": "/report",
            "docs": "/docs"
        }
    }
