"""
Enriquece os CVEs existentes no banco com EPSS (FIRST.org) e recalcula o score.

Uso (a partir da raiz do projeto):
    python3 src/scripts/enrich_epss.py

EPSS é a probabilidade de exploração nos próximos 30 dias — complementa o CISA-KEV
(já explorado) e o CVSS (severidade). A API aceita lote, então o backfill é rápido.
Após gravar epss_score/epss_percentile, zera o score_breakdown dos CVEs afetados
para que recalculate_all_scores reconstrua o breakdown já com o EPSS exposto.
"""

import sys
from pathlib import Path

from sqlalchemy import text

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.storage.database import DatabaseManager, engine  # noqa: E402
from src.enrichers.epss_enricher import fetch_epss          # noqa: E402


def main() -> None:
    db = DatabaseManager()

    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT id, value FROM iocs WHERE type = 'cve'")
        ).fetchall()

    total = len(rows)
    if total == 0:
        print("[enrich_epss] nenhum CVE no banco — nada a fazer.")
        return

    print(f"[enrich_epss] {total} CVEs — buscando EPSS em lote…")
    scores = fetch_epss([value for _, value in rows])
    print(f"[enrich_epss] EPSS retornado para {len(scores)} CVEs")

    updated = 0
    with engine.connect() as conn:
        for ioc_id, value in rows:
            data = scores.get(value)
            if not data:
                continue
            conn.execute(
                text("""
                    UPDATE iocs
                    SET epss_score = :epss, epss_percentile = :pct
                    WHERE id = :id
                """),
                {"epss": data["epss"], "pct": data["percentile"], "id": ioc_id},
            )
            updated += 1
            if updated % 200 == 0:
                conn.commit()
        conn.commit()

    print(f"[enrich_epss] {updated} CVEs atualizados com EPSS")

    if updated > 0:
        print("[enrich_epss] recalculando score_breakdown dos CVEs enriquecidos…")
        # Zera o breakdown dos CVEs com EPSS (status recalculável) para reconstruí-lo
        # já com epss no type_severity. recalculate_all_scores cobre NULL breakdown.
        with engine.connect() as conn:
            conn.execute(text("""
                UPDATE iocs SET score_breakdown = NULL
                WHERE type = 'cve' AND epss_score IS NOT NULL
                  AND (ioc_status IS NULL OR ioc_status IN ('ACTIVE', 'REACTIVATED'))
            """))
            conn.commit()
        recalculated = db.recalculate_all_scores()
        print(f"[enrich_epss] score_breakdown recalculado para {recalculated} IOCs")


if __name__ == "__main__":
    main()
