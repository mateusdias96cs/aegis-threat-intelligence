from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

DISPLAY_LIMIT = 1000
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def compute_trends(iocs: list, days: int = 30) -> list:
    cutoff = datetime.now() - timedelta(days=days)
    counts = defaultdict(lambda: {
        "total": 0, "critical": 0,
        "high": 0, "medium": 0, "low": 0
    })
    for ioc in iocs:
        date_str = str(ioc.get("first_seen", ""))[:10]
        if not date_str:
            continue
        try:
            d = datetime.strptime(date_str, "%Y-%m-%d")
            if d >= cutoff:
                counts[date_str]["total"] += 1
                sev = ioc.get("severity", "").lower()
                if sev in counts[date_str]:
                    counts[date_str][sev] += 1
        except Exception:
            continue
    return [{"date": k, **v} for k, v in sorted(counts.items())]


def generate(iocs: list, stats: dict, techniques: dict = None):
    template_dir = Path(__file__).resolve().parents[2] / "templates"
    output_path = Path(__file__).resolve().parents[2] / "output" / "index.html"

    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
    template = env.get_template("report.html")

    total_in_db = len(iocs)
    trends = compute_trends(iocs)

    iocs = sorted(
        iocs,
        key=lambda x: (
            SEVERITY_ORDER.get((x.get("severity") or "LOW").upper(), 3),
            x.get("first_seen") or "",
        ),
        reverse=False,
    )[:DISPLAY_LIMIT]

    total_displayed = len(iocs)

    html = template.render(
        iocs=iocs,
        stats=stats,
        techniques=techniques or {},
        trends=trends,
        generated_at=datetime.now(timezone(timedelta(hours=-3))).strftime("%Y-%m-%d %H:%M:%S"),
        total=total_displayed,
        total_in_db=total_in_db,
        total_displayed=total_displayed,
        total_in_db_fmt=f"{total_in_db:,}",
        total_displayed_fmt=f"{total_displayed:,}",
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        output_path.write_text(html, encoding="utf-8")
    except OSError as e:
        # Non-fatal on ephemeral filesystems (e.g. Render) — DB is the durable store
        print(f"[html_report] disk write failed (non-fatal): {e}")

    # Always persist to the database so the report survives restarts and deploys
    try:
        from src.storage.database import DatabaseManager
        db = DatabaseManager()
        try:
            db.save_report(html)
            print("[html_report] report saved to database")
        finally:
            db.close()
    except Exception as e:
        print(f"[html_report] database save failed: {e}")
        raise
