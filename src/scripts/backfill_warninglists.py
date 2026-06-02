"""Backfill de warninglists (P2) sobre os IOCs já no banco.

1. Roda o WarningListChecker sobre todo IP/domain/url existente e grava
   `fp_warning` (nome da lista que casou) — ou NULL se deixou de casar.
2. Para os IOCs recém-marcados que estão ACTIVE/REACTIVATED, zera o
   score_breakdown e chama recalculate_all_scores, que reaplica a penalidade
   de provável-FP no score (mesmo padrão do enrich_epss).

Pré-requisito: rodar antes `python -m src.scripts.refresh_warninglists`.
Uso:  .venv/bin/python -m src.scripts.backfill_warninglists
"""

import sys

from sqlalchemy import text

from src.processors.warninglist import get_checker
from src.storage.database import DatabaseManager


def run() -> int:
    checker = get_checker()
    if not checker.loaded:
        print("[backfill] nenhuma warninglist em data/warninglists/ — rode refresh_warninglists primeiro.")
        return 1
    print(f"[backfill] {len(checker.lists)} listas carregadas")

    db = DatabaseManager()
    s = db._session
    rows = s.execute(text(
        "SELECT id, type, value, fp_warning, ioc_status FROM iocs "
        "WHERE type IN ('ip', 'domain', 'url')"
    )).mappings().all()

    set_stmt = text("UPDATE iocs SET fp_warning = :fp WHERE id = :id")
    changed, flagged_active_ids = 0, []
    batch = []
    for r in rows:
        hit = checker.check({"type": r["type"], "value": r["value"]})
        if hit != r["fp_warning"]:
            batch.append({"id": r["id"], "fp": hit})
            changed += 1
        # recém-marcado e vigente → precisa recalcular o score com penalidade
        if hit and not r["fp_warning"] and (r["ioc_status"] is None or r["ioc_status"] in ("ACTIVE", "REACTIVATED")):
            flagged_active_ids.append(r["id"])
        if len(batch) >= 500:
            s.execute(set_stmt, batch); s.commit(); batch.clear()
    if batch:
        s.execute(set_stmt, batch); s.commit()

    print(f"[backfill] fp_warning atualizado em {changed} IOCs; "
          f"{len(flagged_active_ids)} ativos recém-marcados para recálculo")

    # Libera o breakdown dos recém-marcados ativos → recalculate reaplica a penalidade.
    for i in range(0, len(flagged_active_ids), 500):
        chunk = flagged_active_ids[i:i + 500]
        ph = ",".join(f":i{j}" for j in range(len(chunk)))
        s.execute(
            text(f"UPDATE iocs SET score_breakdown = NULL WHERE id IN ({ph})"),
            {f"i{j}": v for j, v in enumerate(chunk)},
        )
        s.commit()

    if flagged_active_ids:
        print("[backfill] recalculando scores dos IOCs marcados ...")
        db.recalculate_all_scores()

    db.close()
    print("[backfill] concluído.")
    return 0


if __name__ == "__main__":
    sys.exit(run())
