from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import FileResponse, HTMLResponse
from pathlib import Path

from src.collectors import cisa, otx, mitre
from src.collectors import abuseipdb
from src.processors import normalizer, classifier, deduplicator
from src.storage.database import DatabaseManager
from src.reporters import html_report
from src.main import run as run_pipeline_task

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
async def run_pipeline(background_tasks: BackgroundTasks):
    background_tasks.add_task(run_pipeline_task)
    return {
        "status": "processing",
        "message": "O pipeline de inteligência foi iniciado em segundo plano! Demora alguns minutos. Aguarde e recarregue a página inicial daqui a pouco para ver o painel gerado."
    }

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
