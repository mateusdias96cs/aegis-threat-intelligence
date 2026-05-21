"""
Enriches existing CVEs in the database with CVSS scores from NVD.

Usage (from project root):
    python3 src/scripts/enrich_cvss.py

After updating all cvss_score fields, recalculates score_breakdown for every
IOC that is now stale (recalculate_all_scores processes those with NULL breakdown,
so we NULL-out the breakdown for affected rows first to trigger a full recalc).
"""

import sys
import time
from pathlib import Path

import requests
from sqlalchemy import text

# Allow imports from project root regardless of cwd
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.storage.database import DatabaseManager, engine  # noqa: E402

_NVD_API     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_SLEEP   = 0.7
_NVD_TIMEOUT = 5


def _fetch_cvss(cve_id: str) -> float | None:
    """Returns the highest-priority CVSS base score from NVD, or None on failure."""
    try:
        resp = requests.get(_NVD_API, params={"cveId": cve_id}, timeout=_NVD_TIMEOUT)
        resp.raise_for_status()
        items = resp.json().get("vulnerabilities", [])
        if not items:
            return None
        metrics = items[0].get("cve", {}).get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                score = entries[0].get("cvssData", {}).get("baseScore")
                if score is not None:
                    return float(score)
        return None
    except Exception:
        return None


def main() -> None:
    db = DatabaseManager()

    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT id, value FROM iocs WHERE type = 'cve' AND cvss_score IS NULL")
        ).fetchall()

    total = len(rows)
    if total == 0:
        print("[enrich_cvss] no CVEs with missing CVSS — nothing to do.")
        return

    print(f"[enrich_cvss] {total} CVEs to enrich from NVD…")

    updated = 0
    not_found = 0

    with engine.connect() as conn:
        for i, (ioc_id, cve_value) in enumerate(rows, 1):
            score = _fetch_cvss(cve_value)

            if score is not None:
                conn.execute(
                    text("UPDATE iocs SET cvss_score = :score WHERE id = :id"),
                    {"score": score, "id": ioc_id},
                )
                print(f"  [{i}/{total}] {cve_value}: CVSS {score}")
                updated += 1
            else:
                print(f"  [{i}/{total}] {cve_value}: não encontrado")
                not_found += 1

            if i % 50 == 0:
                conn.commit()
                print(f"  … committed batch at {i}/{total}")

            if i < total:
                time.sleep(_NVD_SLEEP)

        conn.commit()

    print(f"\n[enrich_cvss] concluído — {updated} atualizados, {not_found} não encontrados")

    if updated > 0:
        print("[enrich_cvss] recalculando score_breakdown para CVEs atualizados…")
        # Null-out breakdown for CVEs that now have a cvss_score so recalculate picks them up
        with engine.connect() as conn:
            conn.execute(
                text("""
                    UPDATE iocs
                    SET score_breakdown = NULL
                    WHERE type = 'cve' AND cvss_score IS NOT NULL
                """)
            )
            conn.commit()

        recalculated = db.recalculate_all_scores()
        print(f"[enrich_cvss] score_breakdown recalculado para {recalculated} IOCs")


if __name__ == "__main__":
    main()
