"""
Calcula a Completude de Contexto (D3) de TODOS os IOCs já no banco.

Uso (a partir da raiz do projeto):
    python3 src/scripts/backfill_context.py

Mede, por IOC, quantas dimensões de contexto aplicáveis ao seu tipo estão
preenchidas (geo, ASN, reputação, superfície, família de malware, severidade,
exploração, tática MITRE, atribuição, corroboração) e grava context_score +
context_breakdown. Idempotente — pode rodar quantas vezes quiser.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.storage.database import DatabaseManager   # noqa: E402


def main() -> None:
    db = DatabaseManager()
    try:
        n = db.backfill_context_completeness()
        print(f"[backfill_context] concluído — {n} IOCs processados.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
