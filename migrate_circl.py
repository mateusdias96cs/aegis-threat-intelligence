#!/usr/bin/env python3
"""
Migração standalone das colunas do CIRCL Passive DNS + Passive SSL.

Adiciona (ADD COLUMN IF NOT EXISTS — idempotente) as colunas usadas pelos
enrichers `circl_pdns_enricher` e `circl_pssl_enricher` na tabela `iocs`.
Compatível com PostgreSQL (produção/Render) e SQLite (local).

Uso:
    python migrate_circl.py

Observação: importar `src.storage.database` JÁ executa a migração completa
(o bloco `_DECAY_COLUMNS` roda na importação e inclui estas colunas). Este
script existe para rodar a migração de forma explícita/auditável e reportar
o que foi criado vs. o que já existia, sem depender de subir a aplicação.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sqlalchemy import text
from src.storage.database import engine  # importar já dispara a migração base

_CIRCL_COLUMNS = [
    # Passive DNS
    ("pdns_record_count",       "INTEGER"),
    ("pdns_first_seen",         "TIMESTAMP"),
    ("pdns_last_seen",          "TIMESTAMP"),
    ("pdns_resolutions",        "TEXT"),
    ("pdns_associated_ips",     "TEXT"),
    ("pdns_associated_domains", "TEXT"),
    ("pdns_suspicious",         "INTEGER DEFAULT 0"),
    ("pdns_enriched_at",        "TIMESTAMP"),
    # Passive SSL
    ("pssl_cert_count",   "INTEGER"),
    ("pssl_certificates", "TEXT"),
    ("pssl_subjects",     "TEXT"),
    ("pssl_self_signed",  "INTEGER DEFAULT 0"),
    ("pssl_expired",      "INTEGER DEFAULT 0"),
    ("pssl_suspicious",   "INTEGER DEFAULT 0"),
    ("pssl_enriched_at",  "TIMESTAMP"),
]


def _existing_columns() -> set[str]:
    dialect = engine.dialect.name
    with engine.connect() as conn:
        if dialect == "postgresql":
            rows = conn.execute(text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'iocs'"
            )).fetchall()
            return {r[0] for r in rows}
        # SQLite
        rows = conn.execute(text("PRAGMA table_info(iocs)")).fetchall()
        return {r[1] for r in rows}


def migrate() -> None:
    dialect = engine.dialect.name
    before = _existing_columns()
    added, skipped = [], []

    for name, ddl in _CIRCL_COLUMNS:
        if name in before:
            skipped.append(name)
            continue
        sql = (
            f"ALTER TABLE iocs ADD COLUMN IF NOT EXISTS {name} {ddl}"
            if dialect == "postgresql"
            else f"ALTER TABLE iocs ADD COLUMN {name} {ddl}"
        )
        try:
            with engine.connect() as conn:
                conn.execute(text(sql))
                conn.commit()
            added.append(name)
        except Exception as e:
            print(f"  ! falha ao adicionar {name}: {e}")

    print(f"[migrate_circl] dialeto: {dialect}")
    print(f"[migrate_circl] colunas adicionadas ({len(added)}): {', '.join(added) or '—'}")
    print(f"[migrate_circl] já existentes ({len(skipped)}): {', '.join(skipped) or '—'}")
    print("[migrate_circl] concluído.")


if __name__ == "__main__":
    migrate()
