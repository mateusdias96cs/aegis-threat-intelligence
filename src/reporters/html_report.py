from datetime import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader


def generate(iocs: list, stats: dict, techniques: dict = None):
    template_dir = Path(__file__).resolve().parents[2] / "templates"
    output_path = Path(__file__).resolve().parents[2] / "output" / "index.html"

    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
    template = env.get_template("report.html")

    html = template.render(
        iocs=iocs,
        stats=stats,
        techniques=techniques or {},
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total=len(iocs),
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        output_path.write_text(html, encoding="utf-8")
    except OSError as e:
        print(f"[html_report] failed to write report: {e}")
        raise
