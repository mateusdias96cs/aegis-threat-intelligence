"""Backfill de RDAP para domínios e URLs já no banco.

Busca todos os IOCs do tipo domain/url sem rdap_data, consulta o RDAP
em lote e grava o resultado. Para os que têm age_days discriminador
(< 180d), zera o score_breakdown para forçar recálculo do T.

Uso:  .venv/bin/python -m src.scripts.enrich_rdap
"""

import json
import sys
from sqlalchemy import text
from src.enrichers.rdap_enricher import enrich_batch
from src.storage.database import DatabaseManager


def run() -> int:
    db = DatabaseManager()
    s  = db._session

    rows = s.execute(text("""
        SELECT id, type, value, ioc_status
        FROM iocs
        WHERE type IN ('domain', 'url')
          AND rdap_data IS NULL
          AND (ioc_status IS NULL OR ioc_status NOT IN ('FALSE_POSITIVE'))
        ORDER BY id
    """)).mappings().all()

    if not rows:
        print("[enrich_rdap] nenhum domínio/URL sem rdap_data — nada a fazer.")
        db.close()
        return 0

    print(f"[enrich_rdap] {len(rows)} domínios/URLs para enriquecer")

    iocs = [{"id": r["id"], "type": r["type"], "value": r["value"],
             "ioc_status": r["ioc_status"]} for r in rows]
    enrich_batch(iocs)

    updated = 0
    recalc_ids = []
    BATCH = 500
    upd_stmt = text("UPDATE iocs SET rdap_data = :rdap WHERE id = :id")
    null_stmt = text("UPDATE iocs SET score_breakdown = NULL WHERE id = :id")

    batch = []
    for ioc in iocs:
        rdap = ioc.get("rdap_data")
        if not rdap:
            continue
        batch.append({"id": ioc["id"], "rdap": json.dumps(rdap)})
        age = rdap.get("age_days")
        status = ioc.get("ioc_status")
        if age is not None and age < 180 and (status is None or status in ("ACTIVE", "REACTIVATED")):
            recalc_ids.append(ioc["id"])
        if len(batch) >= BATCH:
            s.execute(upd_stmt, batch); s.commit()
            updated += len(batch); batch.clear()
    if batch:
        s.execute(upd_stmt, batch); s.commit()
        updated += len(batch)

    print(f"[enrich_rdap] {updated} IOCs com rdap_data gravado; "
          f"{len(recalc_ids)} com age_days < 180d para recálculo de score")

    for i in range(0, len(recalc_ids), BATCH):
        chunk = recalc_ids[i:i + BATCH]
        ph = ",".join(f":i{j}" for j in range(len(chunk)))
        s.execute(text(f"UPDATE iocs SET score_breakdown = NULL WHERE id IN ({ph})"),
                  {f"i{j}": v for j, v in enumerate(chunk)})
        s.commit()

    if recalc_ids:
        print("[enrich_rdap] recalculando scores ...")
        db.recalculate_all_scores()

    db.close()
    print("[enrich_rdap] concluído.")
    return 0


if __name__ == "__main__":
    sys.exit(run())
