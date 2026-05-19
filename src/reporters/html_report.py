from datetime import datetime, timezone, timedelta
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

DISPLAY_LIMIT = 1000
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def generate(iocs: list, stats: dict, techniques: dict = None):
    template_dir = Path(__file__).resolve().parents[2] / "templates"
    output_path = Path(__file__).resolve().parents[2] / "output" / "index.html"

    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
    template = env.get_template("report.html")

    total_in_db = len(iocs)

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
        print(f"[html_report] failed to write report: {e}")
        raise
